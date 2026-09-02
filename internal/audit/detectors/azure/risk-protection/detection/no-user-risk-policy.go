package detection

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	RISK_NO_USER_RISK_POLICY = "RISK_NO_USER_RISK_POLICY"
)

type NoUserRiskPolicyDetector struct {
	audit.BaseDetector
}

func NewNoUserRiskPolicyDetector() *NoUserRiskPolicyDetector {
	return &NoUserRiskPolicyDetector{
		BaseDetector: audit.NewBaseDetector(
			RISK_NO_USER_RISK_POLICY,
			audit.CategoryRiskProtection,
		),
	}
}

func (d *NoUserRiskPolicyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "No User Risk Policy",
		Description: "No CA policy uses user risk conditions. User risk policies force password change for compromised users.",
		Count:       0,
	}

	hasUserRiskPolicy := false
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State == "enabled" && len(policy.UserRiskLevels) > 0 {
			hasUserRiskPolicy = true
			break
		}
	}

	if !hasUserRiskPolicy {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = []types.AffectedEntity{
				{
					Type:        "tenant",
					DN:          "tenant",
					Name:        "Azure AD Tenant",
					Description: "No enabled Conditional Access policy uses user risk conditions",
				},
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoUserRiskPolicyDetector())
}
