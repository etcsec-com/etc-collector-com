package membership

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DynamicRuleBroadDetector checks for groups with broad dynamic membership rules
type DynamicRuleBroadDetector struct {
	audit.BaseDetector
}

// NewDynamicRuleBroadDetector creates a new detector
func NewDynamicRuleBroadDetector() *DynamicRuleBroadDetector {
	return &DynamicRuleBroadDetector{
		BaseDetector: audit.NewBaseDetector("AZ_GROUP_DYNAMIC_RULE_BROAD", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *DynamicRuleBroadDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group

	// Heuristic: Groups with more than 100 members may have broad dynamic rules
	for _, group := range data.Groups {
		totalMembers := len(group.Members) + len(group.Member)
		if totalMembers > 100 {
			affected = append(affected, group)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Groups with Broad Dynamic Rules",
		Description: "Dynamic groups with broad membership rules may include unintended users.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDynamicRuleBroadDetector())
}
