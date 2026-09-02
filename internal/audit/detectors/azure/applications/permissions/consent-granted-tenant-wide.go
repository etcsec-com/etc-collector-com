package permissions

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDConsentGrantedTenantWide       = "APP_CONSENT_GRANTED_TENANT_WIDE"
	CategoryConsentGrantedTenantWide = audit.CategoryApplications
)

type ConsentGrantedTenantWideDetector struct {
	audit.BaseDetector
}

func NewConsentGrantedTenantWideDetector() *ConsentGrantedTenantWideDetector {
	return &ConsentGrantedTenantWideDetector{
		BaseDetector: audit.NewBaseDetector(IDConsentGrantedTenantWide, CategoryConsentGrantedTenantWide),
	}
}

func (d *ConsentGrantedTenantWideDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedGrants []types.OAuth2PermissionGrant

	for _, grant := range data.AzureOAuth2PermissionGrants {
		if grant.ConsentType == "AllPrincipals" {
			affectedGrants = append(affectedGrants, grant)
		}
	}

	finding := types.Finding{
		Type:        IDConsentGrantedTenantWide,
		Severity:    types.SeverityHigh,
		Category:    string(CategoryConsentGrantedTenantWide),
		Title:       "Tenant-Wide Consent Grants",
		Description: "OAuth2 permissions granted for all users (tenant-wide consent). Review for excessive access. Consider granting permissions to specific users instead of all principals.",
		Count:       len(affectedGrants),
	}

	if data.IncludeDetails && len(affectedGrants) > 0 {
		finding.AffectedEntities = helpers.ToAffectedOAuth2GrantEntities(affectedGrants)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewConsentGrantedTenantWideDetector())
}
