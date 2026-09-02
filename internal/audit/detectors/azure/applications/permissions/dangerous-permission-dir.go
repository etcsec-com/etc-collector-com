package permissions

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDDangerousPermissionDir       = "APP_DANGEROUS_PERMISSION_DIR"
	CategoryDangerousPermissionDir = audit.CategoryApplications
)

type DangerousPermissionDirDetector struct {
	audit.BaseDetector
}

func NewDangerousPermissionDirDetector() *DangerousPermissionDirDetector {
	return &DangerousPermissionDirDetector{
		BaseDetector: audit.NewBaseDetector(IDDangerousPermissionDir, CategoryDangerousPermissionDir),
	}
}

func (d *DangerousPermissionDirDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedApps []types.AppRegistration

	dirReadWriteAllID := types.DangerousGraphPermissions["Directory.ReadWrite.All"]

	for _, app := range data.AzureAppRegistrations {
		for _, resource := range app.RequiredResourceAccess {
			if resource.ResourceAppID != types.MicrosoftGraphAppID {
				continue
			}

			for _, perm := range resource.Permissions {
				if perm.Type == "Role" && perm.ID == dirReadWriteAllID {
					affectedApps = append(affectedApps, app)
					break
				}
			}
		}
	}

	finding := types.Finding{
		Type:        IDDangerousPermissionDir,
		Severity:    types.SeverityCritical,
		Category:    string(CategoryDangerousPermissionDir),
		Title:       "App with Dangerous Directory Permissions",
		Description: "Applications with Directory.ReadWrite.All can modify all directory objects. Use more specific permissions like User.ReadWrite.All or Group.ReadWrite.All.",
		Count:       len(affectedApps),
	}

	if data.IncludeDetails && len(affectedApps) > 0 {
		finding.AffectedEntities = helpers.ToAffectedAppEntities(affectedApps)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDangerousPermissionDirDetector())
}
