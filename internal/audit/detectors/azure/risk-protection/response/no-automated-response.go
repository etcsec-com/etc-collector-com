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

func (d *NoAutomatedResponseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "No Automated Risk Response",
		Description: "No CA policy automates response to user or sign-in risks. Configure automatic remediation.",
		Count:       0,
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
