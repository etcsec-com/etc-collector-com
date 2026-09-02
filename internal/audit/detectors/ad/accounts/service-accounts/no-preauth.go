package serviceaccounts

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoPreauthDetector detects service accounts without pre-authentication
type NoPreauthDetector struct {
	audit.BaseDetector
}

// NewNoPreauthDetector creates a new detector
func NewNoPreauthDetector() *NoPreauthDetector {
	return &NoPreauthDetector{
		BaseDetector: audit.NewBaseDetector("SERVICE_ACCOUNT_NO_PREAUTH", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *NoPreauthDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if !isServiceAccount(u) {
			continue
		}
		if u.Disabled {
			continue
		}
		if (u.UserAccountControl & types.UACDontRequirePreauth) != 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Service Account Without Pre-Authentication (AS-REP Roasting)",
		Description: "Service accounts with 'Do not require Kerberos pre-authentication' enabled. Attackers can request AS-REP tickets and crack them offline.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Enable Kerberos pre-authentication for all service accounts.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoPreauthDetector())
}
