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
//
// Known limitation (non vu, not fixable in this detector alone):
// ConditionalAccessPolicy.GrantControls only captures grantControls'
// builtInControls (internal/providers/azure/client.go calls
// gc.GetBuiltInControls(), never gc.GetAuthenticationStrength()). A policy
// that requires MFA-equivalent protection through the newer "Require
// authentication strength" grant control instead of the classic "mfa"
// built-in control - the two are mutually exclusive on the same policy per
// Microsoft Graph (Microsoft Learn, "How Authentication Strengths Work in a
// Conditional Access Policy", learn.microsoft.com/en-us/entra/identity/
// authentication/concept-authentication-strength-how-it-works) - is
// invisible to this check and gets wrongly reported as "no MFA policy".
// Confirmed against a real tenant that has exactly such a policy. Fixing
// this needs a new field on types.ConditionalAccessPolicy and a collector
// change, both out of this detector's scope.
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
		Type:     d.ID(),
		Severity: types.SeverityCritical,
		Category: string(d.Category()),
		Title:    "No CA Policy Requires MFA",
		Description: "No enabled CA policy requires multi-factor authentication via the classic 'mfa' " +
			"grant control. A policy that requires MFA-equivalent protection through an authentication " +
			"strength grant control instead is not currently detected (collector does not capture " +
			"authenticationStrength on Conditional Access policies).",
		Count: count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoMFARequirementDetector())
}
