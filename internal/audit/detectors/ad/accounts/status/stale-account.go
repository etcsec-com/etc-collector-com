package status

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// StaleAccountDetector detects stale accounts (180+ days inactive)
type StaleAccountDetector struct {
	audit.BaseDetector
}

// NewStaleAccountDetector creates a new detector
func NewStaleAccountDetector() *StaleAccountDetector {
	return &StaleAccountDetector{
		BaseDetector: audit.NewBaseDetector("STALE_ACCOUNT", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *StaleAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	now := data.Now
	sixMonthsAgo := now.AddDate(0, -6, 0)

	for _, u := range data.Users {
		// Must be enabled
		if u.Disabled {
			continue
		}
		// Check if last logon is older than 180 days
		if u.LastLogon.IsZero() {
			continue
		}
		if u.LastLogon.Before(sixMonthsAgo) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Stale Account (180+ Days)",
		Description: "Enabled user accounts inactive for 180+ days. Stale accounts increase attack surface and should be reviewed.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewStaleAccountDetector())
}
