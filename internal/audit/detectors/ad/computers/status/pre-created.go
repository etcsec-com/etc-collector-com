package status

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PreCreatedDetector checks for pre-created (staging) computer accounts
type PreCreatedDetector struct {
	audit.BaseDetector
}

// NewPreCreatedDetector creates a new detector
func NewPreCreatedDetector() *PreCreatedDetector {
	return &PreCreatedDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_PRE_CREATED", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *PreCreatedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		// Disabled computer that has never logged on
		if !c.Disabled {
			continue
		}

		// Check if it has never logged on
		if c.LastLogon.IsZero() {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Computer Pre-Created (Staging)",
		Description: "Disabled computer accounts that have never logged on. These are staging accounts that were created but never deployed. Should be reviewed and cleaned up.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPreCreatedDetector())
}
