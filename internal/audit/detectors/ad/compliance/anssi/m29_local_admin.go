package anssi

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ANSSI Guide d'hygiène M29 - Limiter au strict besoin opérationnel les
// droits d'administration sur les postes de travail.
//
// Source: https://messervices.cyber.gouv.fr/documents-guides/guide_hygiene_informatique_anssi.pdf
//
// v3.1.18 - REWRITE: this detector now reads the actual GptTmpl.inf
// [Group Membership] stanza (parsed by smb.parseGroupMembership) and reports
// whether at least one GPO in the audited domain restricts the local
// BUILTIN\Administrators group (S-1-5-32-544) to a specific set of SIDs
// instead of letting it accumulate accounts uncontrolled.
//
// Previous heuristic (matching on GPO display name) is gone - false positive
// rate was unacceptable for a "zero bullshit" ANSSI claim.

// builtinAdministratorsSID is the well-known SID for BUILTIN\Administrators
// - the local group that controls workstation/server local-admin rights.
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
		// rather than emit a false positive - we can't decide.
		return nil
	}

	// Walk every GPO and look for a [Group Membership] entry that pins
	// BUILTIN\Administrators to a specific member set.
	//
	// Fixed two false-positive bugs, both confirmed by tracing
	// gptmpl_parser.go (out of scope here - parser/struct
	// fixes noted below):
	//
	//  1. Principal by NAME: MS-GPSB's ABNF for a [Group Membership] line
	//     allows the principal before "__Members" to be written either as a
	//     SID (*S-1-5-32-544__Members=...) or as a bare group name
	//     (Administrators__Members=...). parseGroupMembership stores
	//     whichever form was used, verbatim, into RestrictedGroupSpec.
	//     GroupSID (gptmpl_parser.go:381-387) - so a GPO authored with the
	//     name form was compared only against the SID constant below and
	//     never matched, even though it genuinely restricts local admins.
	//     Fixed by isBuiltinAdministratorsPrincipal accepting either form.
	//
	//  2. Empty Members list indistinguishable from absent: the previous
	//     check required rg.MembersSIDs != nil, reasoning that a configured-
	//     but-empty Members list ("restrict to nobody", the strictest
	//     possible hardening) would still be non-nil. That's wrong:
	//     parseSIDList("") - what a value-less "*S-1-5-32-544__Members="
	//     line parses to - returns nil (strings.Split on an empty string
	//     yields one empty element, which gets trimmed away and never
	//     appended), identical to what a GPO that only sets "__Memberof"
	//     for this principal (or omits it in a way that still creates a
	//     RestrictedGroupSpec) produces. A domain that had explicitly locked
	//     BUILTIN\Administrators down to zero members - the strictest
	//     possible M29 compliance - was flagged as an M29 violation.
	//     RestrictedGroupSpec doesn't expose whether the "Members" key was
	//     literally present (vs. absent, vs. only "Memberof" set) - that
	//     distinction needs a parser-level change in gptmpl_parser.go /
	//     audit.RestrictedGroupSpec, both out of scope here;
	//     noted as a follow-up. Until then, matching on the
	//     principal alone (regardless of the resulting Members slice)
	//     trades a narrow, largely theoretical false negative (a GPO that
	//     sets only "Memberof" for BUILTIN\Administrators - not a pattern
	//     that corresponds to any real-world Restricted Groups authoring
	//     flow for a BUILTIN group) against a demonstrated false positive on
	//     genuinely hardened domains, which is the worse failure mode for
	//     an audit tool.
	for _, p := range data.GPOPolicies {
		if p == nil {
			continue
		}
		for _, rg := range p.RestrictedGroups {
			if isBuiltinAdministratorsPrincipal(rg.GroupSID) {
				// At least one GPO restricts local Admins → M29 met.
				return nil
			}
		}
	}

	return wrapFinding(d, "ANSSI Guide M29 - No GPO restricts local Administrators",
		fmt.Sprintf("ANSSI Guide d'hygiène M29 requires limiting local-administrator rights on workstations to strict operational need. None of the %d parsed GPO(s) defines a [Group Membership] / Restricted Groups entry pinning BUILTIN\\Administrators (SID %s) to a specific member set. Without it, any privileged user who logs in interactively can persist as a local admin via classic abuse paths.", len(data.GPOPolicies), builtinAdministratorsSID),
		types.SeverityMedium, 1, nil)
}

// isBuiltinAdministratorsPrincipal reports whether principal (the raw value
// gptmpl_parser.parseGroupMembership stored in RestrictedGroupSpec.GroupSID)
// identifies the local BUILTIN\Administrators group - either by its
// well-known SID or by the bare name a GPO author can use instead per
// MS-GPSB's ABNF for [Group Membership] entries.
func isBuiltinAdministratorsPrincipal(principal string) bool {
	return principal == builtinAdministratorsSID || strings.EqualFold(principal, "administrators")
}

func init() {
	audit.MustRegister(NewM29LocalAdminNotRestrictedDetector())
}
