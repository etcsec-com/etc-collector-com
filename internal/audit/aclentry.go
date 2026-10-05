package audit

import (
	"strings"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AccessMask bits we care about (v3.1.29 §4 enum). Order is most-specific-first
// because a mask can combine multiple bits (e.g. WriteDACL+WriteOwner under a
// GenericAll rollup) - we pick the most semantically meaningful one for the
// emitted aclEntry.
const (
	maskGenericAll     = 0x10000000
	maskGenericWrite   = 0x40000000
	maskWriteDACL      = 0x00040000
	maskWriteOwner     = 0x00080000
	maskAllExtRights   = 0x00000100 // CONTROL_ACCESS / extended right when ObjectType == ""
	maskWriteProperty  = 0x00000020 // requires ObjectType GUID to be meaningful
	maskValidatedWrite = 0x00000008 // self-validated write
	maskSelfMembership = 0x00000008 // same as ValidatedWrite, distinguished by ObjectType GUID
)

// Well-known control access right (extended right) GUIDs.
const (
	guidDSReplicationGetChanges    = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	guidDSReplicationGetChangesAll = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
	guidUserForceChangePassword    = "00299570-246d-11d0-a768-00aa006e0529"
	guidWriteSPN                   = "f3a64788-5306-11d1-a9c5-0000f80367c1" // Validated-SPN
	guidSelfMembership             = "bf9679c0-0de6-11d0-a285-00aa003049e2" // Self-Membership

	// guidApplyGroupPolicy is the Rights-GUID of the Apply-Group-Policy
	// extended right (learn.microsoft.com/windows/win32/adschema/
	// r-apply-group-policy, updated 2020-12-14): CN Apply-Group-Policy,
	// Applies-To Group-Policy-Container. It is a CONTROL_ACCESS (extended)
	// right, never a bit of the access mask. ADS_RIGHT_DELETE
	// (learn.microsoft.com/windows/win32/api/iads/ne-iads-ads_rights_enum)
	// is a different, unrelated right: 0x00010000, the right to delete the
	// GPO - not to apply it.
	guidApplyGroupPolicy = "edacfd8f-ffb3-11d1-b41d-00a0c968f939"
)

// GrantsApplyGroupPolicy reports whether one ACE grants the Apply-Group-Policy
// extended right: CONTROL_ACCESS (0x00000100) set, and ObjectType either the
// Apply-Group-Policy GUID above or empty - a CONTROL_ACCESS ACE with no
// ObjectType grants EVERY extended right (same convention as maskAllExtRights
// above), Apply-Group-Policy included. A WriteProperty (or any other
// non-CONTROL_ACCESS) ACE never grants it, regardless of ObjectType - the
// right kind of access matters as much as the right GUID.
func GrantsApplyGroupPolicy(mask int, objectType string) bool {
	if mask&maskAllExtRights == 0 {
		return false
	}
	return objectType == "" || strings.EqualFold(objectType, guidApplyGroupPolicy)
}

// IsGrantACE reports whether an ACE actually GRANTS its access mask, i.e. it is
// an ACCESS_ALLOWED / ACCESS_ALLOWED_OBJECT ace rather than a deny or audit one
// (DET_10).
//
// The values come from acl_parser.go's aceTypeToString: ACCESS_ALLOWED,
// ACCESS_DENIED, SYSTEM_AUDIT, ACCESS_ALLOWED_OBJECT, ACCESS_DENIED_OBJECT,
// SYSTEM_AUDIT_OBJECT, UNKNOWN_<n>. Testing for "ALLOWED" rejects the denies
// (which carry "DENIED"), the audit entries, and anything unrecognised -
// failing closed on an ACE whose semantics we cannot establish.
//
// DCSYNC_CAPABLE previously compared AceType to the literal "deny", which no
// parser output can ever equal: the guard never ran.
func IsGrantACE(aceType string) bool {
	return strings.Contains(strings.ToUpper(aceType), "ALLOWED")
}

// AccessMaskToRight returns the canonical right name for an ACE, picking the
// single most security-relevant bit (or the extended-right GUID's friendly
// name when present). Returns "" for ACEs we don't surface as aclEntry -
// callers should skip those.
func AccessMaskToRight(mask int, objectType string) string {
	gt := strings.ToLower(objectType)

	// Object-specific extended rights first - the GUID disambiguates.
	if gt != "" {
		switch gt {
		case guidDSReplicationGetChanges:
			return "DS-Replication-Get-Changes"
		case guidDSReplicationGetChangesAll:
			return "DS-Replication-Get-Changes-All"
		case guidUserForceChangePassword:
			return "User-Force-Change-Password"
		case guidWriteSPN:
			return "WriteSPN"
		case guidSelfMembership:
			return "Self-Membership"
		}
		// Unknown extended right with WriteProperty bit → expose as
		// WriteProperty:<guid> so the SaaS can still render something.
		if mask&maskWriteProperty != 0 {
			return "WriteProperty:" + objectType
		}
	}

	// Mask-only rights, most specific first.
	switch {
	case mask&maskGenericAll != 0:
		return "GenericAll"
	case mask&maskWriteDACL != 0:
		return "WriteDACL"
	case mask&maskWriteOwner != 0:
		return "WriteOwner"
	case mask&maskGenericWrite != 0:
		return "GenericWrite"
	case mask&maskAllExtRights != 0 && objectType == "":
		return "AllExtendedRights"
	case mask&maskWriteProperty != 0:
		return "WriteProperty"
	}
	return ""
}

// ACLEntryToAffectedEntity emits the v3.1.29 §4 aclEntry shape for a single
// ACE, looking up trustee + target via the engine's caches. Returns the zero
// value (Type == "") when the ACE doesn't map to a known right - callers
// should skip those rather than emit a malformed aclEntry.
func ACLEntryToAffectedEntity(ace types.ACLEntry, byDN map[string]*ObjectMeta, bySID map[string]*ObjectMeta) types.AffectedEntity {
	right := AccessMaskToRight(ace.AccessMask, ace.ObjectType)
	if right == "" {
		return types.AffectedEntity{}
	}
	trustee := resolveTrusteeRef(ace.Trustee, bySID)
	target := resolveTargetRef(ace.ObjectDN, byDN)
	inherit := "explicit"
	if ace.IsInherited {
		inherit = "inherited"
	}
	return types.AffectedEntity{
		Type:        types.EntityTypeACLEntry,
		Trustee:     &trustee,
		Right:       right,
		Target:      &target,
		Inheritance: inherit,
	}
}

// resolveTrusteeRef builds an EntityRef from a trustee SID, preferring the
// domain-local cache (typed user/group/computer) before falling back to the
// well-known SID lookup, then to an unresolved-principal ref.
func resolveTrusteeRef(sid string, bySID map[string]*ObjectMeta) types.EntityRef {
	if bySID != nil {
		if meta := bySID[sid]; meta != nil {
			return types.EntityRef{
				Type: meta.EntityType,
				DN:   meta.DN,
				SID:  sid,
				Name: meta.Name,
			}
		}
	}
	if info, ok := wellKnownSIDs[sid]; ok {
		return types.EntityRef{
			Type: types.EntityTypeWellKnownSid,
			SID:  sid,
			Name: info.Name,
		}
	}
	return types.EntityRef{
		Type: types.EntityTypePrincipal,
		SID:  sid,
	}
}

// resolveTargetRef builds an EntityRef from a target DN, falling back to a
// principal placeholder when the target wasn't in the cache (rare - orphan
// resolution should have handled it already).
func resolveTargetRef(dn string, byDN map[string]*ObjectMeta) types.EntityRef {
	if byDN != nil {
		if meta := byDN[dn]; meta != nil {
			return types.EntityRef{
				Type: meta.EntityType,
				DN:   meta.DN,
				Name: meta.Name,
			}
		}
	}
	return types.EntityRef{
		Type: types.EntityTypePrincipal,
		DN:   dn,
	}
}

// weakACLDangerousMask mirrors the sibling permission-family detectors
// (schema-permissions.go, dpapi-key-acl.go, admin-sd-holder-modified.go since
// its AccessMask fix): only ACEs granting actual write-level control count as a weak ACL -
// a read-only grant is noise, not a risk. The helpers below reuse this exact definition
// for HasWeakACL rather than inventing a GPO/CA/CertTemplate-specific one.
const weakACLDangerousMask = types.MaskGenericAll | types.MaskWriteDACL | types.MaskWriteOwner | types.MaskWriteProperty

// BuildPrivilegedSIDSet returns the standard privileged-SID exclusion set
// used by the dangerousMask family of detectors (schema-permissions.go,
// dpapi-key-acl.go, admin-sd-holder-modified.go, and the WeakACL* helpers
// below): a non-admin holding a dangerous right is the risk signal; admins
// holding GenericAll on their own objects is normal, not a "weak" ACL.
func BuildPrivilegedSIDSet(domainInfo *types.DomainInfo) map[string]bool {
	privilegedSIDs := make(map[string]bool)
	privilegedSIDs["S-1-5-18"] = true // SYSTEM
	privilegedSIDs["S-1-3-0"] = true  // Creator Owner
	privilegedSIDs["S-1-5-10"] = true // SELF
	if domainInfo != nil && domainInfo.DomainSID != "" {
		for suffix := range types.PrivilegedSIDSuffixes {
			privilegedSIDs[domainInfo.DomainSID+suffix] = true
		}
	}
	return privilegedSIDs
}

// IsWeakACLGrant reports whether one ACE is a "weak ACL" grant under the
// dangerousMask convention: a non-privileged trustee holding
// GenericAll/WriteDACL/WriteOwner/WriteProperty via an ALLOW ace.
func IsWeakACLGrant(aceType, trustee string, mask int, privilegedSIDs map[string]bool) bool {
	if !IsGrantACE(aceType) {
		return false
	}
	if privilegedSIDs[trustee] {
		return false
	}
	return mask&weakACLDangerousMask != 0
}

// WeakACLGPODNs returns the set of GPO DNs (lowercased) whose ACL carries a
// weak grant per the dangerousMask convention, computed fresh from
// data.GPOAcls (GPO.HasWeakACL is declared and read by
// ANSSI_R59_TIER0_OU_POLICIES and ATTACK_PATH_GPO_TO_DA but never assigned
// anywhere; this is computed inline by each reader instead of via a
// collector-side enrichment pass, since populating a struct field between
// collection and detection would need a change in engine.go's collectData -
// internal/audit/engine.go is shared core, deliberately kept stable, and
// detectors already run
// concurrently once collectData returns, so mutating shared GPO/CertTemplate/
// CertAuthority structs from a detector would race). Same computation each
// caller previously would have read off a precomputed field - just done at
// read time instead of write time.
func WeakACLGPODNs(data *DetectorData) map[string]bool {
	privilegedSIDs := BuildPrivilegedSIDSet(data.DomainInfo)
	weak := make(map[string]bool)
	for _, acl := range data.GPOAcls {
		if IsWeakACLGrant(acl.AceType, acl.Trustee, acl.AccessMask, privilegedSIDs) {
			weak[strings.ToLower(acl.GPODN)] = true
		}
	}
	return weak
}

// WeakACLCADNs returns the set of certificate authority DNs (lowercased)
// whose ACL carries a weak grant per the dangerousMask convention (needed because
// CertAuthority.HasWeakACL is declared and read by ANSSI_R36_CA_RISKS but
// never assigned). Unlike GPO ACLs, which are collected into their own
// data.GPOAcls slice, CA ACEs land in the generic data.ACLEntries now that
// engine.go's collectData includes CA DNs in the objectDNs batch (with
// engine.go granted to ad for that one line only) - filtered here by CA DN
// membership, same read-time-not-write-time choice WeakACLGPODNs made above.
func WeakACLCADNs(data *DetectorData) map[string]bool {
	privilegedSIDs := BuildPrivilegedSIDSet(data.DomainInfo)
	caDNs := make(map[string]bool, len(data.CertAuthorities))
	for _, ca := range data.CertAuthorities {
		caDNs[strings.ToLower(ca.DN)] = true
	}
	weak := make(map[string]bool)
	for _, ace := range data.ACLEntries {
		dn := strings.ToLower(ace.ObjectDN)
		if !caDNs[dn] {
			continue
		}
		if IsWeakACLGrant(ace.AceType, ace.Trustee, ace.AccessMask, privilegedSIDs) {
			weak[dn] = true
		}
	}
	return weak
}

// WeakACLTemplateDNs returns the set of certificate template DNs (lowercased)
// whose ACL carries a weak grant per the dangerousMask convention (same gap
// - CertTemplate.HasWeakEnrollmentACL/HasGenericAllPermission are declared and
// read by ADCS_WEAK_PERMISSIONS but never assigned anywhere). Same read-time
// pattern as WeakACLGPODNs/WeakACLCADNs above: engine.go's collectData already
// batches CertTemplate DNs into objectDNs for ESC4 ACL analysis, so their ACEs
// already land in data.ACLEntries - no engine.go change needed.
func WeakACLTemplateDNs(data *DetectorData) map[string]bool {
	privilegedSIDs := BuildPrivilegedSIDSet(data.DomainInfo)
	templateDNs := make(map[string]bool, len(data.CertTemplates))
	for _, t := range data.CertTemplates {
		templateDNs[strings.ToLower(t.DN)] = true
	}
	weak := make(map[string]bool)
	for _, ace := range data.ACLEntries {
		dn := strings.ToLower(ace.ObjectDN)
		if !templateDNs[dn] {
			continue
		}
		if IsWeakACLGrant(ace.AceType, ace.Trustee, ace.AccessMask, privilegedSIDs) {
			weak[dn] = true
		}
	}
	return weak
}
