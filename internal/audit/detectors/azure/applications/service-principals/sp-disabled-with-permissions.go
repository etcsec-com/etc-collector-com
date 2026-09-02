package serviceprincipals

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDSPDisabledWithPermissions       = "SP_DISABLED_WITH_PERMISSIONS"
	CategorySPDisabledWithPermissions = audit.CategoryApplications
)

type SPDisabledWithPermissionsDetector struct {
	audit.BaseDetector
}

func NewSPDisabledWithPermissionsDetector() *SPDisabledWithPermissionsDetector {
	return &SPDisabledWithPermissionsDetector{
		BaseDetector: audit.NewBaseDetector(IDSPDisabledWithPermissions, CategorySPDisabledWithPermissions),
	}
}

func (d *SPDisabledWithPermissionsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedSPs []types.ServicePrincipal

	// Build map of service principals by AppID for quick lookup
	spByAppID := make(map[string]types.ServicePrincipal)
	for _, sp := range data.AzureServicePrincipals {
		spByAppID[sp.AppID] = sp
	}

	// Track unique service principals
	seenSPs := make(map[string]bool)

	// Check disabled service principals with permission grants
	for _, grant := range data.AzureOAuth2PermissionGrants {
		if sp, exists := spByAppID[grant.ClientID]; exists && !sp.AccountEnabled {
			if !seenSPs[sp.ID] {
				seenSPs[sp.ID] = true
				affectedSPs = append(affectedSPs, sp)
			}
		}
	}

	finding := types.Finding{
		Type:        IDSPDisabledWithPermissions,
		Severity:    types.SeverityMedium,
		Category:    string(CategorySPDisabledWithPermissions),
		Title:       "Disabled Service Principals with Permissions",
		Description: "Disabled service principals still have permission grants. Remove permissions from unused SPs. Remove permissions or delete unused service principals.",
		Count:       len(affectedSPs),
	}

	if data.IncludeDetails && len(affectedSPs) > 0 {
		finding.AffectedEntities = helpers.ToAffectedServicePrincipalEntities(affectedSPs)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSPDisabledWithPermissionsDetector())
}
