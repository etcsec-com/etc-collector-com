package anssi

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ANSSI Guide d'hygiène M29 — Limiter au strict besoin opérationnel les
// droits d'administration sur les postes de travail.
//
// Source: https://messervices.cyber.gouv.fr/documents-guides/guide_hygiene_informatique_anssi.pdf
//
// v3.1.18 — REWRITE: this detector now reads the actual GptTmpl.inf
// [Group Membership] stanza (parsed by smb.parseGroupMembership) and reports
// whether at least one GPO in the audited domain restricts the local
// BUILTIN\Administrators group (S-1-5-32-544) to a specific set of SIDs
// instead of letting it accumulate accounts uncontrolled.
//
// Previous heuristic (matching on GPO display name) is gone — false positive
// rate was unacceptable for a "zero bullshit" ANSSI claim.

// builtinAdministratorsSID is the well-known SID for BUILTIN\Administrators
// — the local group that controls workstation/server local-admin rights.
const builtinAdministratorsSID = "S-1-5-32-544"

type M29LocalAdminNotRestrictedDetector struct{ audit.BaseDetector }

func NewM29LocalAdminNotRestrictedDetector() *M29LocalAdminNotRestrictedDetector {
	return &M29LocalAdminNotRestrictedDetector{
		BaseDetector: audit.NewBaseDetector("M29_LOCAL_ADMIN_NOT_RESTRICTED", audit.CategoryCompliance),
	}
}

func (d *M29LocalAdminNotRestrictedDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	if len(data.GPOPolicies) == 0 {
		// No GPO data parsed (SYSVOL unreachable or no policies). Skip
		// rather than emit a false positive — we can't decide.
		return nil
	}

	// Walk every GPO and look for a [Group Membership] entry that pins
	// BUILTIN\Administrators to a specific member set (Members != nil even
	// if empty list — that means "no one in local Administrators").
	for _, p := range data.GPOPolicies {
		if p == nil {
			continue
		}
		for _, rg := range p.RestrictedGroups {
			if rg.GroupSID == builtinAdministratorsSID && rg.MembersSIDs != nil {
				// At least one GPO restricts local Admins → M29 met.
				return nil
			}
		}
	}

	return wrapFinding(d, "ANSSI Guide M29 — No GPO restricts local Administrators",
		fmt.Sprintf("ANSSI Guide d'hygiène M29 requires limiting local-administrator rights on workstations to strict operational need. None of the %d parsed GPO(s) defines a [Group Membership] / Restricted Groups entry pinning BUILTIN\\Administrators (SID %s) to a specific member set. Without it, any privileged user who logs in interactively can persist as a local admin via classic abuse paths.", len(data.GPOPolicies), builtinAdministratorsSID),
		types.SeverityMedium, 1, nil)
}

func init() {
	audit.MustRegister(NewM29LocalAdminNotRestrictedDetector())
}
