package standards

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	AZ_CIS_BENCHMARK_GAPS = "AZ_CIS_BENCHMARK_GAPS"
)

type CISBenchmarkGapsDetector struct {
	audit.BaseDetector
}

func NewCISBenchmarkGapsDetector() *CISBenchmarkGapsDetector {
	return &CISBenchmarkGapsDetector{
		BaseDetector: audit.NewBaseDetector(
			AZ_CIS_BENCHMARK_GAPS,
			audit.CategoryAzureCompliance,
		),
	}
}

func (d *CISBenchmarkGapsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "CIS Benchmark Compliance Gaps",
		Description: "Multiple CIS Azure AD benchmark recommendations are not implemented.",
		Count:       0,
	}

	var gaps []types.AffectedEntity

	// Check 1: Security defaults disabled
	if data.AzureTenantConfig != nil && data.AzureTenantConfig.SecurityDefaults != nil {
		if !data.AzureTenantConfig.SecurityDefaults.IsEnabled {
			finding.Count++
			if data.IncludeDetails {
				gaps = append(gaps, types.AffectedEntity{
					Type:        "gap",
					Name:        "Security Defaults Disabled",
					Description: "CIS: Security Defaults should be enabled or replaced with CA policies",
				})
			}
		}
	}

	// Check 2: No MFA CA policy
	hasMFAPolicy := false
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State == "enabled" {
			for _, control := range policy.GrantControls {
				if control == "mfa" {
					hasMFAPolicy = true
					break
				}
			}
		}
		if hasMFAPolicy {
			break
		}
	}
	if !hasMFAPolicy {
		finding.Count++
		if data.IncludeDetails {
			gaps = append(gaps, types.AffectedEntity{
				Type:        "gap",
				Name:        "No MFA Policy",
				Description: "CIS: MFA should be enforced via Conditional Access",
			})
		}
	}

	// Check 3: Legacy auth allowed (check for legacy auth block policy)
	hasLegacyAuthBlock := false
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State == "enabled" {
			// Check if policy blocks legacy auth
			if len(policy.ClientAppTypes) > 0 {
				for _, appType := range policy.ClientAppTypes {
					if appType == "exchangeActiveSync" || appType == "other" {
						for _, control := range policy.GrantControls {
							if control == "block" {
								hasLegacyAuthBlock = true
								break
							}
						}
					}
					if hasLegacyAuthBlock {
						break
					}
				}
			}
		}
		if hasLegacyAuthBlock {
			break
		}
	}
	if !hasLegacyAuthBlock {
		finding.Count++
		if data.IncludeDetails {
			gaps = append(gaps, types.AffectedEntity{
				Type:        "gap",
				Name:        "Legacy Auth Not Blocked",
				Description: "CIS: Legacy authentication protocols should be blocked",
			})
		}
	}

	// Check 4: No risk policies
	hasRiskPolicies := false
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State == "enabled" && (len(policy.SignInRiskLevels) > 0 || len(policy.UserRiskLevels) > 0) {
			hasRiskPolicies = true
			break
		}
	}
	if !hasRiskPolicies {
		finding.Count++
		if data.IncludeDetails {
			gaps = append(gaps, types.AffectedEntity{
				Type:        "gap",
				Name:        "No Risk Policies",
				Description: "CIS: Risk-based policies should be configured",
			})
		}
	}

	if finding.Count > 0 && data.IncludeDetails {
		finding.AffectedEntities = gaps
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCISBenchmarkGapsDetector())
}
