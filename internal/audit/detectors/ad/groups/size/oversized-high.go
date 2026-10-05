package size

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// OversizedHighDetector checks for groups with 200-500 members
type OversizedHighDetector struct {
	audit.BaseDetector
}

// NewOversizedHighDetector creates a new detector
func NewOversizedHighDetector() *OversizedHighDetector {
	return &OversizedHighDetector{
		BaseDetector: audit.NewBaseDetector("OVERSIZED_GROUP_HIGH", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *OversizedHighDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group

	for _, group := range data.Groups {
		memberCount := len(group.Member)
		if memberCount > 200 && memberCount <= 500 {
			affected = append(affected, group)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Oversized Group (High)",
		Description: "Groups with 200-500 members. Management difficulty and potential privilege creep.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewOversizedHighDetector())
}
