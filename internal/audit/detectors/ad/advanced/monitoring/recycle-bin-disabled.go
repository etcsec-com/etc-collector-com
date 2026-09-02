package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// RecycleBinDisabledDetector detects if AD Recycle Bin is disabled
type RecycleBinDisabledDetector struct {
	audit.BaseDetector
}

// NewRecycleBinDisabledDetector creates a new detector
func NewRecycleBinDisabledDetector() *RecycleBinDisabledDetector {
	return &RecycleBinDisabledDetector{
		BaseDetector: audit.NewBaseDetector("RECYCLE_BIN_DISABLED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *RecycleBinDisabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		return []types.Finding{{
			Type:        d.ID(),
			Severity:    types.SeverityLow,
			Category:    string(d.Category()),
			Title:       "AD Recycle Bin Status Unknown",
			Description: "Unable to determine AD Recycle Bin status.",
			Count:       0,
		}}
	}

	recycleBinEnabled := data.DomainInfo.RecycleBinEnabled

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "AD Recycle Bin Not Enabled",
		Description: "Active Directory Recycle Bin is not enabled. Deleted objects cannot be easily recovered, which complicates incident response and may lead to permanent data loss.",
		Count:       0,
	}

	if !recycleBinEnabled {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = []types.AffectedEntity{types.DomainInfoToAffectedEntity(data.DomainInfo)}
			finding.Details = map[string]interface{}{
				"recommendation": "Enable AD Recycle Bin feature. Note: This requires forest functional level 2008 R2 or higher and is irreversible.",
				"currentStatus":  "Disabled",
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewRecycleBinDisabledDetector())
}
