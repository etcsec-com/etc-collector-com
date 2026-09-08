package status

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminCountDetector checks for computers with adminCount attribute
type AdminCountDetector struct {
	audit.BaseDetector
}

// NewAdminCountDetector creates a new detector
func NewAdminCountDetector() *AdminCountDetector {
	return &AdminCountDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_ADMIN_COUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *AdminCountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if c.AdminCount {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Computer adminCount Set",
		Description: "Computer with adminCount attribute set to 1. May indicate current or former administrative privileges.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminCountDetector())
}
