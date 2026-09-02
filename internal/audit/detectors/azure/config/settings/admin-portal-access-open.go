package settings

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	AZ_ADMIN_PORTAL_ACCESS_OPEN = "AZ_ADMIN_PORTAL_ACCESS_OPEN"
)

type AdminPortalAccessOpenDetector struct {
	audit.BaseDetector
}

func NewAdminPortalAccessOpenDetector() *AdminPortalAccessOpenDetector {
	return &AdminPortalAccessOpenDetector{
		BaseDetector: audit.NewBaseDetector(
			AZ_ADMIN_PORTAL_ACCESS_OPEN,
			audit.CategoryConfig,
		),
	}
}

func (d *AdminPortalAccessOpenDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Admin Portal Access Not Restricted",
		Description: "Non-admin users can access the Azure AD admin portal. Restrict to prevent information disclosure.",
		Count:       0,
	}

	if data.AzureTenantConfig == nil {
		return []types.Finding{finding}
	}

	if data.AzureTenantConfig.AdminPortalAccess == "" || data.AzureTenantConfig.AdminPortalAccess != "restricted" {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = []types.AffectedEntity{
				{
					Type:        "tenant",
					DN:          "tenant",
					Name:        "Azure AD Tenant",
					Description: "Admin portal access is not restricted to administrators only",
				},
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminPortalAccessOpenDetector())
}
