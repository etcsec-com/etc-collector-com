package registrations

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDAppMultiTenant       = "APP_MULTI_TENANT"
	CategoryAppMultiTenant = audit.CategoryApplications
)

type AppMultiTenantDetector struct {
	audit.BaseDetector
}

func NewAppMultiTenantDetector() *AppMultiTenantDetector {
	return &AppMultiTenantDetector{
		BaseDetector: audit.NewBaseDetector(IDAppMultiTenant, CategoryAppMultiTenant),
	}
}

func (d *AppMultiTenantDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedApps []types.AppRegistration

	for _, app := range data.AzureAppRegistrations {
		if app.SignInAudience == "AzureADMultipleOrgs" || app.SignInAudience == "AzureADandPersonalMicrosoftAccount" {
			affectedApps = append(affectedApps, app)
		}
	}

	finding := types.Finding{
		Type:        IDAppMultiTenant,
		Severity:    types.SeverityMedium,
		Category:    string(CategoryAppMultiTenant),
		Title:       "Multi-Tenant Application Registrations",
		Description: "Applications accepting sign-ins from any Azure AD tenant. Review if multi-tenant access is needed. Restrict to single tenant unless multi-tenant access is required.",
		Count:       len(affectedApps),
	}

	if data.IncludeDetails && len(affectedApps) > 0 {
		finding.AffectedEntities = helpers.ToAffectedAppEntities(affectedApps)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAppMultiTenantDetector())
}
