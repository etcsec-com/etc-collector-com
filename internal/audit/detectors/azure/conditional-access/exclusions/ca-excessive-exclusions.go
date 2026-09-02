package exclusions

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ExcessiveExclusionsDetector checks for CA policies with excessive exclusions
type ExcessiveExclusionsDetector struct {
	audit.BaseDetector
}

// NewExcessiveExclusionsDetector creates a new detector
func NewExcessiveExclusionsDetector() *ExcessiveExclusionsDetector {
	return &ExcessiveExclusionsDetector{
		BaseDetector: audit.NewBaseDetector("CA_EXCESSIVE_EXCLUSIONS", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
func (d *ExcessiveExclusionsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.ConditionalAccessPolicy

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State != "enabled" {
			continue
		}

		totalExclusions := len(p.ExcludeUsers) + len(p.ExcludeGroups)
		if totalExclusions > 10 {
			affected = append(affected, p)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "CA Policies with Excessive Exclusions",
		Description: "CA policies with many user/group exclusions weaken security coverage.",
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
	audit.MustRegister(NewExcessiveExclusionsDetector())
}
