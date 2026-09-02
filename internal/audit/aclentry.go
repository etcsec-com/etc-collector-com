package audit

import (
	"strings"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AccessMask bits we care about (v3.1.29 §4 enum). Order is most-specific-first
// because a mask can combine multiple bits (e.g. WriteDACL+WriteOwner under a
// GenericAll rollup) — we pick the most semantically meaningful one for the
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
)

// IsGrantACE reports whether an ACE actually GRANTS its access mask, i.e. it is
// an ACCESS_ALLOWED / ACCESS_ALLOWED_OBJECT ace rather than a deny or audit one
// (T_024 / DET_10).
//
// The values come from acl_parser.go's aceTypeToString: ACCESS_ALLOWED,
// ACCESS_DENIED, SYSTEM_AUDIT, ACCESS_ALLOWED_OBJECT, ACCESS_DENIED_OBJECT,
// SYSTEM_AUDIT_OBJECT, UNKNOWN_<n>. Testing for "ALLOWED" rejects the denies
// (which carry "DENIED"), the audit entries, and anything unrecognised —
// failing closed on an ACE whose semantics we cannot establish.
//
// DCSYNC_CAPABLE previously compared AceType to the literal "deny", which no
// parser output can ever equal: the guard never ran.
func IsGrantACE(aceType string) bool {
	return strings.Contains(strings.ToUpper(aceType), "ALLOWED")
}

// AccessMaskToRight returns the canonical right name for an ACE, picking the
// single most security-relevant bit (or the extended-right GUID's friendly
// name when present). Returns "" for ACEs we don't surface as aclEntry —
// callers should skip those.
func AccessMaskToRight(mask int, objectType string) string {
	gt := strings.ToLower(objectType)

	// Object-specific extended rights first — the GUID disambiguates.
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
// value (Type == "") when the ACE doesn't map to a known right — callers
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
// principal placeholder when the target wasn't in the cache (rare — orphan
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
