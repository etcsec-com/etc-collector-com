package status

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DisabledNotDeletedDetector checks for disabled computers not deleted (>30 days)
type DisabledNotDeletedDetector struct {
	audit.BaseDetector
}

// NewDisabledNotDeletedDetector creates a new detector
func NewDisabledNotDeletedDetector() *DisabledNotDeletedDetector {
	return &DisabledNotDeletedDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_DISABLED_NOT_DELETED", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *DisabledNotDeletedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	now := data.Now
	thirtyDaysAgo := now.AddDate(0, 0, -30)

	var affected []types.Computer

	for _, c := range data.Computers {
		// Only check disabled computers
		if !c.Disabled {
			continue
		}

		// Check if whenChanged is older than 30 days
		if c.WhenChanged.IsZero() {
			continue
		}

		if c.WhenChanged.Before(thirtyDaysAgo) {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Computer Disabled Not Deleted",
		Description: "Disabled computer not deleted (>30 days). Clutters AD, potential security oversight.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDisabledNotDeletedDetector())
}
