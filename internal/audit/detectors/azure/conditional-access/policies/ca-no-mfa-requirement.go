package policies

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoMFARequirementDetector checks if any CA policy requires MFA
type NoMFARequirementDetector struct {
	audit.BaseDetector
}

// NewNoMFARequirementDetector creates a new detector
func NewNoMFARequirementDetector() *NoMFARequirementDetector {
	return &NoMFARequirementDetector{
		BaseDetector: audit.NewBaseDetector("CA_NO_MFA_REQUIREMENT", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
func (d *NoMFARequirementDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasMFAPolicy := false

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State == "enabled" && containsStr(p.GrantControls, "mfa") {
			hasMFAPolicy = true
			break
		}
	}

	count := 0
	if !hasMFAPolicy {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "No CA Policy Requires MFA",
		Description: "No enabled CA policy requires multi-factor authentication in its grant controls.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoMFARequirementDetector())
}
