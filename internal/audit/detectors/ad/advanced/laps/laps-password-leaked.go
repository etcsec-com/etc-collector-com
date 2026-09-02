package laps

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LapsPasswordLeakedDetector detects LAPS passwords with excessive readers
type LapsPasswordLeakedDetector struct {
	audit.BaseDetector
}

// NewLapsPasswordLeakedDetector creates a new detector
func NewLapsPasswordLeakedDetector() *LapsPasswordLeakedDetector {
	return &LapsPasswordLeakedDetector{
		BaseDetector: audit.NewBaseDetector("LAPS_PASSWORD_LEAKED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *LapsPasswordLeakedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		// Check if LAPS password has excessive readers (populated by ACL analysis)
		if c.LAPSPasswordExcessiveReaders {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "LAPS Password Leaked",
		Description: "LAPS password visible to too many users. Reduces effectiveness of LAPS.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLapsPasswordLeakedDetector())
}
