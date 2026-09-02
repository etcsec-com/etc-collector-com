package laps

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LapsLegacyAttributeDetector detects legacy LAPS attribute usage
type LapsLegacyAttributeDetector struct {
	audit.BaseDetector
}

// NewLapsLegacyAttributeDetector creates a new detector
func NewLapsLegacyAttributeDetector() *LapsLegacyAttributeDetector {
	return &LapsLegacyAttributeDetector{
		BaseDetector: audit.NewBaseDetector("LAPS_LEGACY_ATTRIBUTE", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *LapsLegacyAttributeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		// Has legacy LAPS but not Windows LAPS
		if c.LegacyLAPSPassword != "" && c.WindowsLAPSPassword == "" {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "LAPS Legacy Attribute",
		Description: "Legacy LAPS attribute used instead of Windows LAPS. Less secure implementation.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLapsLegacyAttributeDetector())
}
