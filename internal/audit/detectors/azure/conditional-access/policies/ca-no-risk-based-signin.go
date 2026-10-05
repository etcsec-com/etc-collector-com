package policies

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoRiskBasedSignInDetector checks if any CA policy uses sign-in risk levels
type NoRiskBasedSignInDetector struct {
	audit.BaseDetector
}

// NewNoRiskBasedSignInDetector creates a new detector
func NewNoRiskBasedSignInDetector() *NoRiskBasedSignInDetector {
	return &NoRiskBasedSignInDetector{
		BaseDetector: audit.NewBaseDetector("CA_NO_RISK_BASED_SIGNIN", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
func (d *NoRiskBasedSignInDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasRiskBasedPolicy := false

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State == "enabled" && len(p.SignInRiskLevels) > 0 {
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
		Title:       "No Sign-In Risk-Based CA Policy",
		Description: "No CA policy uses sign-in risk levels. Risk-based policies provide adaptive security.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoRiskBasedSignInDetector())
}
