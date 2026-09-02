package detection

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	RISK_NO_SIGNIN_RISK_POLICY = "RISK_NO_SIGNIN_RISK_POLICY"
)

type NoSignInRiskPolicyDetector struct {
	audit.BaseDetector
}

func NewNoSignInRiskPolicyDetector() *NoSignInRiskPolicyDetector {
	return &NoSignInRiskPolicyDetector{
		BaseDetector: audit.NewBaseDetector(
			RISK_NO_SIGNIN_RISK_POLICY,
			audit.CategoryRiskProtection,
		),
	}
}

func (d *NoSignInRiskPolicyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "No Sign-In Risk Policy",
		Description: "No CA policy uses sign-in risk conditions. Risk-based policies block compromised sign-ins.",
		Count:       0,
	}

	hasSignInRiskPolicy := false
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State == "enabled" && len(policy.SignInRiskLevels) > 0 {
			hasSignInRiskPolicy = true
			break
		}
	}

	if !hasSignInRiskPolicy {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = []types.AffectedEntity{
				{
					Type:        "tenant",
					DN:          "tenant",
					Name:        "Azure AD Tenant",
					Description: "No enabled Conditional Access policy uses sign-in risk conditions",
				},
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoSignInRiskPolicyDetector())
}
