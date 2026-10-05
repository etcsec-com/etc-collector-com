package status

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PasswordOldDetector checks for computers with old passwords (>90 days)
type PasswordOldDetector struct {
	audit.BaseDetector
}

// NewPasswordOldDetector creates a new detector
func NewPasswordOldDetector() *PasswordOldDetector {
	return &PasswordOldDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_PASSWORD_OLD", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *PasswordOldDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	now := data.Now
	ninetyDaysAgo := now.AddDate(0, 0, -90)

	var affected []types.Computer

	for _, c := range data.Computers {
		// Only check enabled computers
		if c.Disabled {
			continue
		}

		// Check passwordLastSet
		if c.PasswordLastSet.IsZero() {
			continue
		}

		if c.PasswordLastSet.Before(ninetyDaysAgo) {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Computer Password Old",
		Description: "Computer password not changed for 90+ days. Increases risk of password-based attacks.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPasswordOldDetector())
}
