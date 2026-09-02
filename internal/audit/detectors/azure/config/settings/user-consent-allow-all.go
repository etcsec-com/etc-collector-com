package settings

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	AZ_USER_CONSENT_ALL = "AZ_USER_CONSENT_ALL"
)

type UserConsentAllowAllDetector struct {
	audit.BaseDetector
}

func NewUserConsentAllowAllDetector() *UserConsentAllowAllDetector {
	return &UserConsentAllowAllDetector{
		BaseDetector: audit.NewBaseDetector(
			AZ_USER_CONSENT_ALL,
			audit.CategoryConfig,
		),
	}
}

func (d *UserConsentAllowAllDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "User Consent Allows All Applications",
		Description: "Users can consent to any application requesting permissions. This enables consent phishing.",
		Count:       0,
	}

	if data.AzureTenantConfig == nil {
		return []types.Finding{finding}
	}

	if data.AzureTenantConfig.UserConsentPolicy == "" || data.AzureTenantConfig.UserConsentPolicy == "unrestricted" {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = []types.AffectedEntity{
				{
					Type:        "tenant",
					DN:          "tenant",
					Name:        "Azure AD Tenant",
					Description: "User consent policy allows all applications",
				},
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUserConsentAllowAllDetector())
}
