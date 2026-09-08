package standards

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	AZ_IDENTITY_PROTECTION_DISABLED = "AZ_IDENTITY_PROTECTION_DISABLED"
)

type IdentityProtectionDisabledDetector struct {
	audit.BaseDetector
}

func NewIdentityProtectionDisabledDetector() *IdentityProtectionDisabledDetector {
	return &IdentityProtectionDisabledDetector{
		BaseDetector: audit.NewBaseDetector(
			AZ_IDENTITY_PROTECTION_DISABLED,
			audit.CategoryAzureCompliance,
		),
	}
}

func (d *IdentityProtectionDisabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Identity Protection Not Configured",
		Description: "Azure AD Identity Protection risk policies are not configured.",
		Count:       0,
	}

	hasRiskBasedPolicies := false
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State == "enabled" && (len(policy.SignInRiskLevels) > 0 || len(policy.UserRiskLevels) > 0) {
			hasRiskBasedPolicies = true
			break
		}
	}

	if !hasRiskBasedPolicies {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = []types.AffectedEntity{
				{
					Type:        "tenant",
					DN:          "tenant",
					Name:        "Azure AD Tenant",
					Description: "No risk-based Conditional Access policies configured",
				},
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewIdentityProtectionDisabledDetector())
}
