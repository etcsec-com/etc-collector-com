package anssi

import (
	"context"
	"strconv"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R18: Group Policy Creator Owners minimal.
//
// Despite the "R18" filename (kept for history), a full-text audit of ANSSI
// PA-099 found this ID does NOT correspond to PA-099 recommendation R18 -
// see the detector's own comment for what the real PA-099 content at that
// number is, and why no citation is used here instead.
//
// This file, anssi-r23-lm-hash-not-disabled.go and
// anssi-r27-kerberos-preauth-not-fast.go used to live together in
// r16_to_r27_privileges_crypto.go. Two adjacent numbers in that range were
// already removed as v3.1.21 dedups before the split:
//   - ANSSI_R17_SCHEMA_ENTERPRISE_ADMINS_NOT_EMPTY: custom
//     SCHEMA_ADMINS_NOT_EMPTY was extended to also check Enterprise Admins,
//     covering R17's full scope. Mapping migrated.
//   - ANSSI_R19_DNSADMINS_NOT_EMPTY: same group as custom
//     DNS_ADMINS_MEMBER. Mapping migrated.
// R20, R21, R22 and R24 are covered by existing detectors and only need
// framework-mapping entries - see internal/audit/compliance/mappings.go.

type R18GPCOMinimalDetector struct{ audit.BaseDetector }

func NewR18GPCOMinimalDetector() *R18GPCOMinimalDetector {
	return &R18GPCOMinimalDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R18_GPCO_NOT_MINIMAL", audit.CategoryCompliance)}
}

// gpcoRIDSuffixes matches Group Policy Creator Owners by its fixed,
// domain-relative RID -520 (Microsoft Learn, "Security identifiers",
// learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers),
// not by its English sAMAccountName: the previous
// EqualFold(g.SAMAccountName, "Group Policy Creator Owners") match was
// blind on a localized forest (the name differs per language) and would
// false-positive on any homonym group whose name matches the English text
// without carrying the real RID. Nested/transitive group membership is not
// followed here (same scope limit as privgroups.IsMemberOfAny).
var gpcoRIDSuffixes = []string{"-520"}

// builtinAdministratorRIDSuffix is the built-in Administrator account's
// fixed, domain-relative RID -500 (same Microsoft Learn source as above).
const builtinAdministratorRIDSuffix = "-500"

// isBuiltinAdministratorRID matches the built-in Administrator account by
// ObjectSID, never by sAMAccountName: a renamed built-in Administrator
// keeps its RID and must stay excluded, while any other account merely
// NAMED "Administrator" carries no such exemption. Same idiom as
// accounts/advanced/admin-count-orphaned.go's isProtectedAccountRID.
func isBuiltinAdministratorRID(objectSID string) bool {
	return strings.HasSuffix(objectSID, builtinAdministratorRIDSuffix)
}

// primaryGroupIsGPCO reports whether u's PRIMARY group - not memberOf; AD
// never writes a memberOf backlink for a user's primary group, so it must
// be checked separately - is Group Policy Creator Owners. u.PrimaryGroupID
// is a bare RID, turned into a full SID by prefixing
// data.DomainInfo.DomainSID and looked up by EXACT match (not suffix) in
// data.ObjectBySID, then confirmed against gpcoDNs (the -520 set built by
// privgroups.DNsBySIDSuffix). Same pattern as
// groups/membership/gpo-modify-rights.go's primaryGroupIsGpoCreatorOwners,
// duplicated here rather than exported to keep this detector independent
// of that package's internals.
//
// When data.DomainInfo or its DomainSID is empty (not collected), no
// membership is granted here: this fails CLOSED, never open, rather than
// trusting an unverifiable RID.
func primaryGroupIsGPCO(data *audit.DetectorData, u types.User, gpcoDNs map[string]bool) bool {
	if data.DomainInfo == nil || data.DomainInfo.DomainSID == "" {
		return false
	}
	primaryGroupSID := data.DomainInfo.DomainSID + "-" + strconv.Itoa(u.PrimaryGroupID)
	meta := data.ObjectBySID[primaryGroupSID]
	if meta == nil {
		return false
	}
	return gpcoDNs[strings.ToLower(meta.DN)]
}

func (d *R18GPCOMinimalDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Default is Administrator (1 member). Anything more deserves scrutiny.
	// The finding previously reported only a bare excess count with
	// no AffectedEntities (motif(c)), which last night's harness confirmed
	// live is inactionable (entity_present=0, unattributable). Members beyond
	// the default Administrator are now resolved and listed.
	gpcoDNs := privgroups.DNsBySIDSuffix(data, gpcoRIDSuffixes)

	seen := make(map[string]bool)
	var excess []types.AffectedEntity

	// countExcess adds dn to excess at most once - seen dedups a DN reached
	// through both the direct-member and primary-group paths below - and
	// skips the built-in Administrator account, identified by RID only.
	countExcess := func(dn, objectSID string) {
		key := strings.ToLower(dn)
		if seen[key] {
			return
		}
		seen[key] = true
		if isBuiltinAdministratorRID(objectSID) {
			return
		}
		excess = append(excess, data.EntityForDN(dn))
	}

	for _, g := range data.Groups {
		if !gpcoDNs[strings.ToLower(g.DN)] {
			continue
		}
		for _, memberDN := range g.Members {
			var objectSID string
			if meta := data.ObjectByDN[memberDN]; meta != nil {
				objectSID = meta.SID
			}
			countExcess(memberDN, objectSID)
		}
	}

	// AD never writes a memberOf backlink for a user's PRIMARY group, so
	// g.Members above never carries a user whose primary group is GPCO -
	// it has to be found this way instead.
	for _, u := range data.Users {
		if primaryGroupIsGPCO(data, u, gpcoDNs) {
			countExcess(u.DN, u.ObjectSID)
		}
	}

	var entities []types.AffectedEntity
	if data.IncludeDetails {
		entities = excess
	}
	// ANSSI PA-099 (full-text source audit): "Group Policy Creator Owners"
	// (or its French name) does not appear anywhere in PA-099's 166 pages.
	// The real R18 is "Appliquer les security baselines aux systèmes du
	// Tier 0" (p.35, Microsoft/CIS-style OS hardening baselines) - unrelated
	// to this AD group. Keeping Group Policy Creator Owners minimal is a
	// recognized general AD hygiene practice, not an ANSSI PA-099 citation.
	return wrapFinding(d, "Group Policy Creator Owners contient des membres en excès (heuristic)",
		"Group Policy Creator Owners should be restricted to the bare minimum. Members can create new GPOs that, once linked, can affect Tier 0 systems if cross-tier links exist. This is a general AD hygiene heuristic; no ANSSI PA-099 recommendation names this specific group.",
		types.SeverityMedium, len(excess), entities)
}

func init() {
	audit.MustRegister(NewR18GPCOMinimalDetector())
}
