package status

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Inactive365Detector detects accounts inactive for 365+ days
type Inactive365Detector struct {
	audit.BaseDetector
}

// NewInactive365Detector creates a new detector
func NewInactive365Detector() *Inactive365Detector {
	return &Inactive365Detector{
		BaseDetector: audit.NewBaseDetector("INACTIVE_365_DAYS", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *Inactive365Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	now := data.Now
	oneYearAgo := now.AddDate(-1, 0, 0)

	for _, u := range data.Users {
		if u.LastLogon.IsZero() {
			continue
		}
		if u.LastLogon.Before(oneYearAgo) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Inactive 365+ Days",
		Description: "User accounts inactive for 365+ days. Should be disabled or deleted.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewInactive365Detector())
}
