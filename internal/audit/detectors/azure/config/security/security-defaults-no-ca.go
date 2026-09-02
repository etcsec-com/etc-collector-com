package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	AZ_SECURITY_DEFAULTS_NO_CA = "AZ_SECURITY_DEFAULTS_NO_CA"
)

type SecurityDefaultsNoCADetector struct {
	audit.BaseDetector
}

func NewSecurityDefaultsNoCADetector() *SecurityDefaultsNoCADetector {
	return &SecurityDefaultsNoCADetector{
		BaseDetector: audit.NewBaseDetector(
			AZ_SECURITY_DEFAULTS_NO_CA,
			audit.CategoryConfig,
		),
	}
}

func (d *SecurityDefaultsNoCADetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Security Defaults Disabled Without CA Policies",
		Description: "Security Defaults are disabled but no Conditional Access policies replace them.",
		Count:       0,
	}

	if data.AzureTenantConfig == nil || data.AzureTenantConfig.SecurityDefaults == nil {
		return []types.Finding{finding}
	}

	securityDefaultsDisabled := !data.AzureTenantConfig.SecurityDefaults.IsEnabled
	noCAPolicies := len(data.AzureConditionalAccessPolicies) == 0

	if securityDefaultsDisabled && noCAPolicies {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = []types.AffectedEntity{
				{
					Type:        "tenant",
					DN:          "tenant",
					Name:        "Azure AD Tenant",
					Description: "Security Defaults disabled with no Conditional Access policies configured",
				},
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSecurityDefaultsNoCADetector())
}
