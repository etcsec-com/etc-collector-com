package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	AZ_SECURITY_DEFAULTS_DISABLED = "AZ_SECURITY_DEFAULTS_DISABLED"
)

type SecurityDefaultsDisabledDetector struct {
	audit.BaseDetector
}

func NewSecurityDefaultsDisabledDetector() *SecurityDefaultsDisabledDetector {
	return &SecurityDefaultsDisabledDetector{
		BaseDetector: audit.NewBaseDetector(
			AZ_SECURITY_DEFAULTS_DISABLED,
			audit.CategoryConfig,
		),
	}
}

func (d *SecurityDefaultsDisabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Security Defaults Disabled",
		Description: "Azure AD Security Defaults are disabled. Security Defaults provide baseline protection including MFA.",
		Count:       0,
	}

	if data.AzureTenantConfig == nil || data.AzureTenantConfig.SecurityDefaults == nil {
		return []types.Finding{finding}
	}

	if !data.AzureTenantConfig.SecurityDefaults.IsEnabled {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = []types.AffectedEntity{
				{
					Type:        "tenant",
					DN:          "tenant",
					Name:        data.AzureTenantConfig.SecurityDefaults.DisplayName,
					Description: "Security Defaults are disabled",
				},
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSecurityDefaultsDisabledDetector())
}
