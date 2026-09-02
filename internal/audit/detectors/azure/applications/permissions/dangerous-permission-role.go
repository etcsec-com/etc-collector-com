package permissions

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDDangerousPermissionRole       = "APP_DANGEROUS_PERMISSION_ROLE"
	CategoryDangerousPermissionRole = audit.CategoryApplications
)

type DangerousPermissionRoleDetector struct {
	audit.BaseDetector
}

func NewDangerousPermissionRoleDetector() *DangerousPermissionRoleDetector {
	return &DangerousPermissionRoleDetector{
		BaseDetector: audit.NewBaseDetector(IDDangerousPermissionRole, CategoryDangerousPermissionRole),
	}
}

func (d *DangerousPermissionRoleDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedApps []types.AppRegistration

	roleManagementID := types.DangerousGraphPermissions["RoleManagement.ReadWrite.Directory"]

	for _, app := range data.AzureAppRegistrations {
		for _, resource := range app.RequiredResourceAccess {
			if resource.ResourceAppID != types.MicrosoftGraphAppID {
				continue
			}

			for _, perm := range resource.Permissions {
				if perm.Type == "Role" && perm.ID == roleManagementID {
					affectedApps = append(affectedApps, app)
					break
				}
			}
		}
	}

	finding := types.Finding{
		Type:        IDDangerousPermissionRole,
		Severity:    types.SeverityCritical,
		Category:    string(CategoryDangerousPermissionRole),
		Title:       "App with Role Management Permissions",
		Description: "Applications with RoleManagement.ReadWrite.Directory can assign any directory role. This permission allows privilege escalation.",
		Count:       len(affectedApps),
	}

	if data.IncludeDetails && len(affectedApps) > 0 {
		finding.AffectedEntities = helpers.ToAffectedAppEntities(affectedApps)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDangerousPermissionRoleDetector())
}
