package anssi

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R59: Restrict security policies on Tier 0 OU ---
//
// R59 (p.74) actually has THREE components:
// 1. the Tier 0 OU must block GPO inheritance from parent OUs/domain root
// (gPOptions) - NOT collected yet (see pkg/types/finding.go's
// blockInheritance comment: "gPOptions not threaded yet"), so this
// detector cannot check it and must not claim to.
// 2. the Default Domain Policy must still be explicitly linked to the
// Tier 0 OU, with the lowest priority - checkable in principle
// (GPOLink.Order/Enforced exist), but ONLY meaningful once (1) is
// known to be true: on a domain that does NOT block inheritance,
// Default Domain Policy correctly reaching the Tier 0 OU via normal
// inheritance, unlinked, is fine. Emitting a finding here without
// knowing (1) would manufacture a new false positive of exactly the
// kind this work exists to remove - left unimplemented for that
// reason, not because the data is unreachable.
// 3. GPOs linked/applied to the Tier 0 OU must be dedicated to Tier 0 and
// modifiable only by Tier 0 admins - the ACL check below. This is the
// ONLY one of the three this detector measures.
//
// Title/description are written to say exactly that, instead of claiming
// full R59 coverage.

type R59Tier0OUPoliciesDetector struct{ audit.BaseDetector }

func NewR59Tier0OUPoliciesDetector() *R59Tier0OUPoliciesDetector {
	return &R59Tier0OUPoliciesDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R59_TIER0_OU_POLICIES", audit.CategoryCompliance),
	}
}

// tier0OUMarkersDN is intentionally narrow to avoid false positives on
// generic "Admin" OUs that are not Tier 0 in the strict sense.
var tier0OUMarkersDN = []string{
	"ou=tier0", "ou=tier-0", "ou=tier 0", "ou=t0", "ou=tier_0", "ou=paw",
}

func (d *R59Tier0OUPoliciesDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// v3.1.19 - extra Tier 0 OU DNs from tier0_groups.yaml.
	customOUs := map[string]bool{}
	if data.Tier0Config != nil {
		for _, dn := range data.Tier0Config.OUs {
			customOUs[strings.ToLower(strings.TrimSpace(dn))] = true
		}
	}

	// Find Tier 0 OUs.
	var tier0OUs []types.OU
	for _, ou := range data.OUs {
		dn := strings.ToLower(ou.DN)
		matched := customOUs[dn]
		if !matched {
			for _, m := range tier0OUMarkersDN {
				if strings.Contains(dn, m) {
					matched = true
					break
				}
			}
		}
		if matched {
			tier0OUs = append(tier0OUs, ou)
		}
	}
	if len(tier0OUs) == 0 {
		// No Tier 0 OU detected - the org may not have one. Don't emit a
		// false positive; this control only makes sense when Tier 0 OU exists.
		return nil
	}
	// Build a map GPO GUID → GPO with weak ACL. GPO.HasWeakACL was
	// never assigned by the collector; computed here instead from
	// data.GPOAcls via the dangerousMask convention (see WeakACLGPODNs).
	weakGPODNs := audit.WeakACLGPODNs(data)
	weakGPOs := map[string]types.GPO{}
	for _, g := range data.GPOs {
		if weakGPODNs[strings.ToLower(g.DN)] {
			weakGPOs[strings.ToLower(g.GUID)] = g
		}
	}
	if len(weakGPOs) == 0 {
		return nil // no weak GPO → R59 is satisfied (nothing risky linked anywhere)
	}
	// Walk GPOLinks and flag links of weak GPOs to Tier 0 OUs.
	tier0DNSet := map[string]bool{}
	for _, ou := range tier0OUs {
		tier0DNSet[strings.ToLower(ou.DN)] = true
	}
	var hits []string
	for _, link := range data.GPOLinks {
		if !link.LinkEnabled || link.Disabled {
			continue
		}
		ref := strings.ToLower(link.GPOCN)
		if ref == "" {
			ref = strings.ToLower(link.GPOGuid)
		}
		// Match GPO by GUID substring against weakGPOs map.
		matched := false
		for guid := range weakGPOs {
			if guid != "" && strings.Contains(ref, guid) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if tier0DNSet[strings.ToLower(link.LinkedTo)] {
			hits = append(hits, fmt.Sprintf("GPO link %s → %s", link.GPOCN, link.LinkedTo))
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return wrapFinding(d, "ANSSI R59 (partial) - Weak-ACL GPO linked to a Tier 0 OU",
		fmt.Sprintf("%d GPO link(s) attach a GPO with a weak ACL (writable by non-admins) to a Tier 0 OU: %s. ", len(hits), strings.Join(hits, "; "))+
			"ANSSI R59 requires GPOs linked to the Tier 0 OU to be dedicated and admin-only-modifiable - this is the ONE of R59's three components this check covers. It does NOT verify that the Tier 0 OU blocks GPO inheritance, nor that the Default Domain Policy is relinked to it at the lowest priority (both required by R59, neither observable with currently-collected data). A low-trust user with write access on a linked GPO can pivot to Tier 0 by editing the policy.",
		types.SeverityCritical, len(hits), nil)
}

func init() {
	audit.MustRegister(NewR59Tier0OUPoliciesDetector())
}
