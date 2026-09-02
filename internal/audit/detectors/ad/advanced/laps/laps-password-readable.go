package laps

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LapsPasswordReadableDetector detects LAPS passwords readable by non-admins
type LapsPasswordReadableDetector struct {
	audit.BaseDetector
}

// NewLapsPasswordReadableDetector creates a new detector
func NewLapsPasswordReadableDetector() *LapsPasswordReadableDetector {
	return &LapsPasswordReadableDetector{
		BaseDetector: audit.NewBaseDetector("LAPS_PASSWORD_READABLE", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *LapsPasswordReadableDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		// Check if LAPS password is readable by non-admins (populated by ACL analysis)
		if c.LAPSPasswordReadableByNonAdmins {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "LAPS Password Readable",
		Description: "Non-admin users can read LAPS password attributes. Exposure of local admin passwords.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLapsPasswordReadableDetector())
}
