package policies

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoRiskBasedUserDetector checks if any CA policy uses user risk levels
type NoRiskBasedUserDetector struct {
	audit.BaseDetector
}

// NewNoRiskBasedUserDetector creates a new detector
func NewNoRiskBasedUserDetector() *NoRiskBasedUserDetector {
	return &NoRiskBasedUserDetector{
		BaseDetector: audit.NewBaseDetector("CA_NO_RISK_BASED_USER", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
func (d *NoRiskBasedUserDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasRiskBasedPolicy := false

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State == "enabled" && len(p.UserRiskLevels) > 0 {
			hasRiskBasedPolicy = true
			break
		}
	}

	count := 0
	if !hasRiskBasedPolicy {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "No User Risk-Based CA Policy",
		Description: "No CA policy uses user risk levels for adaptive protection.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoRiskBasedUserDetector())
}
