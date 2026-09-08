package serviceaccounts

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// OldPasswordDetector detects service accounts with old passwords
type OldPasswordDetector struct {
	audit.BaseDetector
}

// NewOldPasswordDetector creates a new detector
func NewOldPasswordDetector() *OldPasswordDetector {
	return &OldPasswordDetector{
		BaseDetector: audit.NewBaseDetector("SERVICE_ACCOUNT_OLD_PASSWORD", audit.CategoryAccounts),
	}
}

// Detect executes the detection.
//
// pwdLastSet == 0 does NOT mean "password never changed" or "changed long
// ago" - it is AD's explicit "must change password at next logon" marker
// (Microsoft Learn, "Pwd-Last-Set attribute"; [MS-ADA3]): it is set on
// every freshly created or administratively reset account, including ones
// reset minutes ago. The collector maps that LDAP value 0 to a Go zero
// time.Time (parseFileTime), same as an uncollected/absent value, so
// PasswordLastSet.IsZero() previously counted brand-new/just-reset service
// accounts as "not changed in over 1 year" - the exact false claim
// observed on the lab, where every real hit was pwdLastSet=0 on ~7-month
// old accounts, never the genuine >1-year branch. Only a real, non-zero,
// stale timestamp now counts as an old password.
func (d *OldPasswordDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	now := data.Now
	oneYearAgo := now.AddDate(-1, 0, 0)

	for _, u := range data.Users {
		// Must be a service account
		if !isServiceAccount(u) {
			continue
		}
		// Must be enabled
		if u.Disabled {
			continue
		}
		// pwdLastSet == 0 ("must change at next logon") is not an old
		// password - skip it rather than count it as one.
		if u.PasswordLastSet.IsZero() {
			continue
		}
		// Password must be older than 1 year
		if u.PasswordLastSet.Before(oneYearAgo) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Service Account with Old Password",
		Description: "Service accounts with passwords not changed in over 1 year. These accounts are high-value targets and passwords should be rotated regularly.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Rotate service account passwords every 90 days or migrate to gMSA for automatic password management.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewOldPasswordDetector())
}
