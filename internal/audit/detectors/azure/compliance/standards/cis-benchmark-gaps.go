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

// azureConditionalAccessCollectionFailed reports whether the Graph call that
// populates data.AzureConditionalAccessPolicies (GetConditionalAccessPolicies,
// internal/providers/azure/client.go) failed this run - engine.go appends this
// exact warning code when that happens (internal/audit/engine.go). Without
// this guard, checks 2-4 read a nil/empty slice from a failed collection the
// same way they'd read a genuinely empty policy list, and silently count 3
// false gaps instead of reporting "not determinable". Check 1 already avoided
// this trap via its own AzureTenantConfig != nil guard; this mirrors it for
// the CA-policy-backed checks.
func azureConditionalAccessCollectionFailed(warnings []types.Warning) bool {
	for _, w := range warnings {
		if w.Code == "AZURE_CONDITIONAL_ACCESS_POLICIES_FAILED" {
			return true
		}
	}
	return false
}

// Sources for the four checks below (general product-level mapping, not
// per-subcontrol numbers - CIS control numbering has moved across benchmark
// editions, e.g. the standalone "Security Defaults" recommendation present in
// CIS Microsoft 365 Foundations Benchmark v3 was removed in v5.0 in favor of
// Conditional Access coverage; this repo's baseline already anchors on v3,
// see internal/audit/baselinesecurity.go's baselinePolicyDefs sources list):
//   - Check 1: Microsoft Learn "Security defaults in Microsoft Entra ID"
//     (learn.microsoft.com/en-us/entra/fundamentals/security-defaults) +
//     CIS Microsoft 365 Foundations Benchmark v3, "Security Defaults" control.
//   - Check 2: Microsoft Learn "Require MFA for all users with Conditional
//     Access" (learn.microsoft.com/en-us/entra/identity/conditional-access/
//     policy-all-users-mfa-strength) + CIS v3 "Ensure multifactor
//     authentication is enabled for all users" control.
//   - Check 3: Microsoft Learn "Block legacy authentication with Conditional
//     Access" (learn.microsoft.com/en-us/entra/identity/conditional-access/
//     policy-block-legacy-authentication) + CIS v3 "Enable Conditional Access
//     policies to block legacy authentication" control.
//   - Check 4: Microsoft Learn "Risk-based access policies"
//     (learn.microsoft.com/en-us/entra/id-protection/
//     concept-identity-protection-policies) + CIS v3 risk-based Conditional
//     Access control. Note: Microsoft is retiring the *legacy* Identity
//     Protection risk policies (distinct from CA risk conditions, which this
//     check reads) on 2026-10-01 - doesn't change what's checked here.
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
	caCollectionFailed := azureConditionalAccessCollectionFailed(data.Warnings)

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

	// Checks 2-4 all read data.AzureConditionalAccessPolicies. If that
	// collection failed, an empty/nil slice here means "unknown", not "no
	// policies configured" - skip them rather than count 3 false gaps.
	if !caCollectionFailed {
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
	}

	if finding.Count > 0 && data.IncludeDetails {
		finding.AffectedEntities = gaps
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCISBenchmarkGapsDetector())
}
