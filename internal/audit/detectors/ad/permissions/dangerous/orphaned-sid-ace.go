package dangerous

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// orphaned-sid-ace.go — T_042 / B_020. T_023's BadSuccessor fix (isDMSAContainer,
// restricting "container" to real OUs/domain root) removed 286 of 288
// BADSUCCESSOR_DMSA false positives — but those 286 were the ONLY signal ever
// reporting that S-1-5-21-…-93801, a SID with NO live object behind it,
// holds full control (0xF01FF) over 293 accounts. Correct the wrong detector
// and the real exposure it was accidentally surfacing goes dark. These two
// detectors are its dedicated replacement.
//
// Dangerous-rights bits mirror ACL_GENERICALL / ACL_WRITEDACL / ACL_WRITEOWNER
// exactly (same package, siblings) — this pair asks the same "who holds
// dangerous rights" question, filtered to trustees the engine cannot name at
// all, rather than to all trustees.
const (
	orphanGenericAll   = 0x10000000
	orphanFullControl  = 0x000f01ff
	orphanWriteDACL    = 0x00040000
	orphanWriteOwner   = 0x00080000
	orphanGenericWrite = 0x40000000
)

func hasOrphanDangerousRights(mask int) bool {
	return mask&orphanGenericAll != 0 ||
		(mask&orphanFullControl) == orphanFullControl ||
		mask&orphanWriteDACL != 0 ||
		mask&orphanWriteOwner != 0 ||
		mask&orphanGenericWrite != 0
}

// isTrusteeUnresolved reports whether sid names no live principal — neither a
// domain-local object (data.ObjectBySID) nor a static well-known SID.
//
// Delegates entirely to audit.SIDToEntityWithCache, the same resolution chain
// aclEntry/permissions detectors already trust, so this pair can never
// disagree with the rest of the engine about what counts as "resolved". The
// engine's OWN orphan-resolution pass (detector.go, buildObjectIndex/
// EntityForDN) only ever resolves ACL *target* DNs via LDAPProvider.LookupBatch
// — it has no equivalent for a bare trustee SID (LookupBatch takes DNs, and a
// SID alone gives it none), so nothing upstream already answers this
// question. Unresolved here really does mean "the engine could not name it",
// not "the engine didn't try".
func isTrusteeUnresolved(sid string, data *audit.DetectorData) bool {
	return audit.SIDToEntityWithCache(sid, data).Unresolved
}

// isLocalDomainSID reports whether sid's domain-identifying prefix (everything
// before the final RID segment) matches this domain's own SID — i.e. sid
// WOULD be one of our own users/groups/computers if its object still existed,
// rather than a principal from another domain entirely.
//
// Requires data.DomainInfo.DomainSID. Without it we cannot tell "ours" from
// "foreign" — and guessing "ours" would be the same mistake T_042 exists to
// fix a second time (treating a collection gap as a finding), so the missing
// case falls through to false: an unclassifiable SID is handled by
// CROSS_DOMAIN_SID_DANGEROUS_ACE's "cannot verify locally" framing, never by
// ORPHANED_SID_DANGEROUS_ACE's "this used to be one of ours" claim.
func isLocalDomainSID(sid string, data *audit.DetectorData) bool {
	if data.DomainInfo == nil || data.DomainInfo.DomainSID == "" {
		return false
	}
	idx := strings.LastIndex(sid, "-")
	if idx <= 0 {
		return false
	}
	return sid[:idx] == data.DomainInfo.DomainSID
}

// matchedOrphanACEs scans data.ACLEntries once for both detectors below:
// grant ACEs conveying dangerous rights to a trustee SID the engine cannot
// resolve, split by whether that SID's domain prefix is ours (local) or not
// (foreign). Two real causes hide behind an unresolved trustee SID and they
// carry different weight (T_042 F.1): a domain-local SID with no matching
// object is most likely a deleted account — AD does not recycle RIDs in
// normal operation, so re-acquiring that exact SID takes an unusual scenario
// (e.g. sIDHistory injection, which itself requires prior DA-equivalent
// access). A foreign-domain SID is a live trust-abuse vector RIGHT NOW if the
// referencing trust is ever re-established or its DC compromised — and this
// collector, scoped to one domain, has no way to confirm locally whether that
// foreign principal still exists (a legitimate cross-domain grant manifests
// here as a foreignSecurityPrincipal object we currently only COUNT, at
// DomainInfo.ForeignSecurityPrincipalsCount — we do not collect individual
// FSP SIDs, so we cannot cross-reference this specific SID against it; a
// genuine gap, flagged rather than worked around).
func matchedOrphanACEs(data *audit.DetectorData) (local, foreign []types.ACLEntry) {
	for _, ace := range data.ACLEntries {
		if !audit.IsGrantACE(ace.AceType) {
			continue
		}
		if !hasOrphanDangerousRights(ace.AccessMask) {
			continue
		}
		if ace.Trustee == "" || audit.IsBuiltinAdminTrustee(ace.Trustee) {
			continue
		}
		if !isTrusteeUnresolved(ace.Trustee, data) {
			continue
		}
		if isLocalDomainSID(ace.Trustee, data) {
			local = append(local, ace)
		} else {
			foreign = append(foreign, ace)
		}
	}
	return local, foreign
}

// OrphanedSidDangerousACEDetector flags dangerous rights held by a trustee
// SID whose domain prefix is ours, with no matching object — the
// likely-deleted-account case.
type OrphanedSidDangerousACEDetector struct {
	audit.BaseDetector
}

// NewOrphanedSidDangerousACEDetector creates the detector.
func NewOrphanedSidDangerousACEDetector() *OrphanedSidDangerousACEDetector {
	return &OrphanedSidDangerousACEDetector{
		BaseDetector: audit.NewBaseDetector("ORPHANED_SID_DANGEROUS_ACE", audit.CategoryPermissions),
	}
}

// Detect executes the detection.
func (d *OrphanedSidDangerousACEDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	local, _ := matchedOrphanACEs(data)

	uniqueObjects := helpers.GetUniqueObjects(local)
	totalInstances := len(local)

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityHigh,
		Category: string(d.Category()),
		Title:    "Dangerous ACE Granted to an Orphaned Local SID",
		Description: "A grant ACE (GenericAll/full control, WriteDACL, WriteOwner or GenericWrite) " +
			"names a trustee SID whose domain prefix belongs to this domain, but which resolves " +
			"to no user, group, computer, OU or well-known principal — most likely a deleted " +
			"account whose access control entries were never cleaned up. Nobody can currently " +
			"exercise this grant through a normal logon, but the stale ACE should still be " +
			"removed: AD does not recycle RIDs in normal operation, so unlike a live account " +
			"this SID cannot simply be renamed or reset — reclaiming it would require sIDHistory " +
			"injection, which itself presupposes prior privileged access.",
		Count: len(uniqueObjects),
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails && len(uniqueObjects) > 0 {
		finding.AffectedEntities = audit.GetUniqueObjectEntities(local, data.ObjectByDN)
	}

	return []types.Finding{finding}
}

// CrossDomainSidDangerousACEDetector flags dangerous rights held by a trustee
// SID whose domain prefix does NOT match ours — a foreign-domain reference we
// cannot verify from this domain alone.
type CrossDomainSidDangerousACEDetector struct {
	audit.BaseDetector
}

// NewCrossDomainSidDangerousACEDetector creates the detector.
func NewCrossDomainSidDangerousACEDetector() *CrossDomainSidDangerousACEDetector {
	return &CrossDomainSidDangerousACEDetector{
		BaseDetector: audit.NewBaseDetector("CROSS_DOMAIN_SID_DANGEROUS_ACE", audit.CategoryPermissions),
	}
}

// Detect executes the detection.
func (d *CrossDomainSidDangerousACEDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	_, foreign := matchedOrphanACEs(data)

	uniqueObjects := helpers.GetUniqueObjects(foreign)
	totalInstances := len(foreign)

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityCritical,
		Category: string(d.Category()),
		Title:    "Dangerous ACE Granted to an Unverifiable Cross-Domain SID",
		Description: "A grant ACE (GenericAll/full control, WriteDACL, WriteOwner or GenericWrite) " +
			"names a trustee SID from a domain other than this one, with no matching well-known " +
			"or domain-local principal. A legitimate cross-domain grant of this kind normally " +
			"shows up here as a foreignSecurityPrincipal object — this collector currently only " +
			"counts those (see domain summary), it does not enumerate their individual SIDs, so " +
			"this exact SID cannot be confirmed against that count. It may be an intentional, " +
			"still-active trust grant, or a stale reference left behind by a trust that was later " +
			"removed or reconfigured — if the referenced domain is ever reachable again (trust " +
			"re-established, its DC compromised), this SID can be forged via sIDHistory to inherit " +
			"these rights immediately, with no dependency on RID recycling. Verify against the " +
			"domain's current trust relationships before deciding whether to remove it.",
		Count: len(uniqueObjects),
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails && len(uniqueObjects) > 0 {
		finding.AffectedEntities = audit.GetUniqueObjectEntities(foreign, data.ObjectByDN)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewOrphanedSidDangerousACEDetector())
	audit.MustRegister(NewCrossDomainSidDangerousACEDetector())
}
