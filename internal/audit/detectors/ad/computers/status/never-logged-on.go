package status

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NeverLoggedOnDetector checks for enabled computers that have never logged on
type NeverLoggedOnDetector struct {
	audit.BaseDetector
}

// NewNeverLoggedOnDetector creates a new detector
func NewNeverLoggedOnDetector() *NeverLoggedOnDetector {
	return &NeverLoggedOnDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_NEVER_LOGGED_ON", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *NeverLoggedOnDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		// Only check enabled computers
		if c.Disabled {
			continue
		}

		// Check both lastLogon and lastLogonTimestamp
		lastLogonTime := c.LastLogon
		if lastLogonTime.IsZero() {
			lastLogonTime = c.LastLogonTimestamp
		}

		// No logon time means never logged on
		if lastLogonTime.IsZero() {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Computer Never Logged On",
		Description: "Enabled computer accounts that have never authenticated to the domain. These may be orphaned accounts from failed deployments or unused systems that should be cleaned up.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNeverLoggedOnDetector())
}
