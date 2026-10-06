package policies

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PolicyReportOnlyDetector checks for CA policies in report-only mode
type PolicyReportOnlyDetector struct {
	audit.BaseDetector
}

// NewPolicyReportOnlyDetector creates a new detector
func NewPolicyReportOnlyDetector() *PolicyReportOnlyDetector {
	return &PolicyReportOnlyDetector{
		BaseDetector: audit.NewBaseDetector("CA_POLICY_REPORT_ONLY", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
func (d *PolicyReportOnlyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.ConditionalAccessPolicy

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State == "enabledForReportingButNotEnforced" {
			affected = append(affected, p)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Conditional Access Policies in Report-Only Mode",
		Description: "CA policies in report-only mode are not enforced. Review and enable them.",
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
	audit.MustRegister(NewPolicyReportOnlyDetector())
}
