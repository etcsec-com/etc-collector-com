package settings

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	AZ_APP_REGISTRATION_OPEN = "AZ_APP_REGISTRATION_OPEN"
)

type AppRegistrationOpenDetector struct {
	audit.BaseDetector
}

func NewAppRegistrationOpenDetector() *AppRegistrationOpenDetector {
	return &AppRegistrationOpenDetector{
		BaseDetector: audit.NewBaseDetector(
			AZ_APP_REGISTRATION_OPEN,
			audit.CategoryConfig,
		),
	}
}

func (d *AppRegistrationOpenDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "App Registration Open to All Users",
		Description: "Any user can register applications. Restrict to reduce shadow IT.",
		Count:       0,
	}

	if data.AzureTenantConfig == nil {
		return []types.Finding{finding}
	}

	if data.AzureTenantConfig.UserRegistrationAllowed {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = []types.AffectedEntity{
				{
					Type:        "tenant",
					DN:          "tenant",
					Name:        "Azure AD Tenant",
					Description: "All users can register applications",
				},
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAppRegistrationOpenDetector())
}
