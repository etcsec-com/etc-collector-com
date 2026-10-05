package response

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	RISK_NO_AUTOMATED_RESPONSE = "RISK_NO_AUTOMATED_RESPONSE"
)

type NoAutomatedResponseDetector struct {
	audit.BaseDetector
}

func NewNoAutomatedResponseDetector() *NoAutomatedResponseDetector {
	return &NoAutomatedResponseDetector{
		BaseDetector: audit.NewBaseDetector(
			RISK_NO_AUTOMATED_RESPONSE,
			audit.CategoryRiskProtection,
		),
	}
}

// Detect checks for an enabled CA policy that pairs a risk condition with an
// MFA or block grant control.
//
// Known limitation (non vu, not fixable in this detector alone):
// ConditionalAccessPolicy.GrantControls only captures grantControls'
// builtInControls (internal/providers/azure/client.go calls
// gc.GetBuiltInControls(), never gc.GetAuthenticationStrength()) - the same
// gap already documented on CA_NO_MFA_REQUIREMENT. Here it is sharper:
// Microsoft's own recommended control for a risk-based policy is "Require
// risk remediation" (Microsoft Learn, "Risk policies - Microsoft Entra ID
// Protection", learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies,
// section "Microsoft recommendations"), which is implemented as an
// authenticationStrength grant control, not the classic "mfa" built-in
// control this check looks for. A tenant that followed Microsoft's own
// template is invisible to this check and gets wrongly reported as having no
// automated response. Confirmed against a real tenant configured exactly
// this way. Fixing this needs a new field on types.ConditionalAccessPolicy
// and a collector change, both out of this detector's scope.
func (d *NoAutomatedResponseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityHigh,
		Category: string(d.Category()),
		Title:    "No Automated Risk Response",
		Description: "No enabled CA policy pairs a risk condition with the classic 'mfa' or 'block' grant control. A policy " +
			"using Microsoft's recommended 'Require risk remediation' control (an authentication strength grant control) " +
			"instead is not currently detected (collector does not capture authenticationStrength on Conditional Access " +
			"policies).",
		Count: 0,
	}

	hasAutomatedResponse := false
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}

		// Check if policy has risk levels
		hasRiskLevels := len(policy.SignInRiskLevels) > 0 || len(policy.UserRiskLevels) > 0
		if !hasRiskLevels {
			continue
		}

		// Check if it has appropriate grant controls (mfa or block)
		hasControls := false
		for _, control := range policy.GrantControls {
			if control == "mfa" || control == "block" {
				hasControls = true
				break
			}
		}

		if hasRiskLevels && hasControls {
			hasAutomatedResponse = true
			break
		}
	}

	if !hasAutomatedResponse {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = []types.AffectedEntity{
				{
					Type:        "tenant",
					DN:          "tenant",
					Name:        "Azure AD Tenant",
					Description: "No CA policy with automated risk response (risk levels + MFA/block controls)",
				},
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoAutomatedResponseDetector())
}
