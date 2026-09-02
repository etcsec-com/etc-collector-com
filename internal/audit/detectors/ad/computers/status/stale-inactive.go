package status

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// StaleInactiveDetector checks for stale/inactive computers (90+ days)
type StaleInactiveDetector struct {
	audit.BaseDetector
}

// NewStaleInactiveDetector creates a new detector
func NewStaleInactiveDetector() *StaleInactiveDetector {
	return &StaleInactiveDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_STALE_INACTIVE", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *StaleInactiveDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	now := data.Now
	ninetyDaysAgo := now.AddDate(0, 0, -90)

	var affected []types.Computer

	for _, c := range data.Computers {
		// Only check enabled computers
		if c.Disabled {
			continue
		}

		// Try lastLogon first, then lastLogonTimestamp
		lastLogonTime := c.LastLogon
		if lastLogonTime.IsZero() {
			lastLogonTime = c.LastLogonTimestamp
		}

		// Skip if no logon time (handled by COMPUTER_NEVER_LOGGED_ON)
		if lastLogonTime.IsZero() {
			continue
		}

		if lastLogonTime.Before(ninetyDaysAgo) {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Computer Stale/Inactive",
		Description: "Computer inactive for 90+ days. Orphaned computer accounts could be exploited without detection.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewStaleInactiveDetector())
}
