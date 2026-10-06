package size

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// OversizedDetector checks for groups with 100-500 members
type OversizedDetector struct {
	audit.BaseDetector
}

// NewOversizedDetector creates a new detector
func NewOversizedDetector() *OversizedDetector {
	return &OversizedDetector{
		BaseDetector: audit.NewBaseDetector("OVERSIZED_GROUP", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *OversizedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group

	for _, group := range data.Groups {
		memberCount := len(group.Member)
		if memberCount > 100 && memberCount <= 500 {
			affected = append(affected, group)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Oversized Group",
		Description: "Groups with 100-500 members. May indicate overly broad permissions.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewOversizedDetector())
}
