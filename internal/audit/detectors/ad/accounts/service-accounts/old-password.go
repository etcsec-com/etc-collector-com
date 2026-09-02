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

// Detect executes the detection
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
		// Password must be older than 1 year
		if u.PasswordLastSet.IsZero() || u.PasswordLastSet.Before(oneYearAgo) {
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
