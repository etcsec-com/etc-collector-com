package exclusions

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GroupExclusionLargeDetector checks for CA policies with many group exclusions
type GroupExclusionLargeDetector struct {
	audit.BaseDetector
}

// NewGroupExclusionLargeDetector creates a new detector
func NewGroupExclusionLargeDetector() *GroupExclusionLargeDetector {
	return &GroupExclusionLargeDetector{
		BaseDetector: audit.NewBaseDetector("CA_GROUP_EXCLUSION_LARGE", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
func (d *GroupExclusionLargeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.ConditionalAccessPolicy

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State != "enabled" {
			continue
		}

		if len(p.ExcludeGroups) > 5 {
			affected = append(affected, p)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "CA Policies with Large Group Exclusions",
		Description: "CA policies exclude groups that may contain many members, reducing policy effectiveness.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = make([]types.AffectedEntity, len(affected))
		for i, p := range affected {
			finding.AffectedEntities[i] = types.AffectedEntity{
				Type: "conditionalAccessPolicy",
				DN:   p.ID,
				Name: p.DisplayName,
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewGroupExclusionLargeDetector())
}
