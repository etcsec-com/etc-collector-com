package laps

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LapsPasswordSetDetector detects computers with LAPS properly configured
type LapsPasswordSetDetector struct {
	audit.BaseDetector
}

// NewLapsPasswordSetDetector creates a new detector
func NewLapsPasswordSetDetector() *LapsPasswordSetDetector {
	return &LapsPasswordSetDetector{
		BaseDetector: audit.NewBaseDetector("LAPS_PASSWORD_SET", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *LapsPasswordSetDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		// Has any LAPS password set
		if c.LegacyLAPSPassword != "" || c.WindowsLAPSPassword != "" {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "LAPS Password Set",
		Description: "LAPS password successfully managed. Informational - indicates proper LAPS deployment.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLapsPasswordSetDetector())
}
