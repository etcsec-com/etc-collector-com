package advanced

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminCountOrphanedOnDisabledAccountDetector checks the same population as
// AdminCountOrphanedDetector - adminCount=1, not a direct member (memberOf
// or primary group) of any Appendix C protected group, not krbtgt or the
// built-in Administrator by RID - restricted to DISABLED accounts. Split
// out for the same reason as the delegation and Backup Operators families
// (*_ON_DISABLED_ACCOUNT): a disabled account cannot obtain a
// ticket-granting ticket of its own ([MS-KILE] "Check Account Policy for
// Every TGT Request" - KDC_ERR_CLIENT_REVOKED), so it cannot authenticate
// and any residual privilege here is currently dormant. adminCount is not
// removed by disabling the account, so this is not "resolved" - it returns
// to full relevance the instant the account is re-enabled, which is the
// residual risk this detector keeps reporting, at Low rather than Medium.
// Same convention as the rest of the catalog: the suffix names the
// population covered, not the state of a mechanism - _DISABLED alone is
// reserved elsewhere for "a protection was turned off".
type AdminCountOrphanedOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewAdminCountOrphanedOnDisabledAccountDetector creates a new detector
func NewAdminCountOrphanedOnDisabledAccountDetector() *AdminCountOrphanedOnDisabledAccountDetector {
	return &AdminCountOrphanedOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("ADMIN_COUNT_ORPHANED_ON_DISABLED_ACCOUNT", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *AdminCountOrphanedOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	protectedGroupDNs := privgroups.DNsBySIDSuffix(data, protectedGroupSIDSuffixes)

	for _, u := range data.Users {
		if !u.AdminCount {
			continue
		}

		// Active accounts are reported separately, at Medium, by
		// AdminCountOrphanedDetector.
		if !u.Disabled {
			continue
		}

		if isProtectedAccountRID(u.ObjectSID) {
			continue
		}

		if primaryGroupIsProtected(data, u, protectedGroupDNs) {
			continue
		}

		if len(u.MemberOf) == 0 {
			affected = append(affected, u)
			continue
		}

		if !privgroups.IsMemberOfAny(u.MemberOf, protectedGroupDNs) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Orphaned AdminCount Flag (Disabled Account)",
		Description: "Disabled accounts with adminCount=1 that are not a DIRECT member - via memberOf or primary group - of any group AdminSDHolder/SDProp protects (Microsoft Learn, \"Appendix C: Protected Accounts and Groups in Active Directory\", https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory), and are not krbtgt or the built-in Administrator account (identified by RID, not name). A disabled account cannot authenticate ([MS-KILE], \"Check Account Policy for Every TGT Request\", KDC_ERR_CLIENT_REVOKED), so any residual privilege here is currently dormant - but adminCount is not removed by disabling the account, and it returns to full relevance the instant the account is re-enabled. Limitation: membership reached through a NESTED group is not resolved and can still produce a false positive here.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Verify there is no NESTED protected-group membership (direct membership and primary group are already ruled out) before clearing the adminCount flag. If the account is expected to stay disabled and unused, consider removing it instead of re-enabling it later with a stale adminCount flag.",
			"impact":         "Accounts may still have protected ACLs preventing proper management; the account returns to full relevance if re-enabled.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminCountOrphanedOnDisabledAccountDetector())
}
