package permissions

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDDangerousPermissionFiles       = "APP_DANGEROUS_PERMISSION_FILES"
	CategoryDangerousPermissionFiles = audit.CategoryApplications
)

type DangerousPermissionFilesDetector struct {
	audit.BaseDetector
}

func NewDangerousPermissionFilesDetector() *DangerousPermissionFilesDetector {
	return &DangerousPermissionFilesDetector{
		BaseDetector: audit.NewBaseDetector(IDDangerousPermissionFiles, CategoryDangerousPermissionFiles),
	}
}

func (d *DangerousPermissionFilesDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedApps []types.AppRegistration

	// Files.ReadWrite.All (application permission) is documented by Microsoft
	// itself as tenant-wide, unscoped access to "all site collections" /
	// every user's OneDrive - not a heuristic threshold, an actual Graph
	// permission scope. Source: Microsoft Graph permissions reference,
	// learn.microsoft.com/en-us/graph/permissions-reference, entry
	// "Files.ReadWrite.All" (Application). No live-tenant true positive has
	// been observed for this check yet (status: non vu, not verified) -
	// CHECKS.yml tracking for this ID is out of scope here.
	filesReadWriteAllID := types.DangerousGraphPermissions["Files.ReadWrite.All"]

	for _, app := range data.AzureAppRegistrations {
		for _, resource := range app.RequiredResourceAccess {
			if resource.ResourceAppID != types.MicrosoftGraphAppID {
				continue
			}

			for _, perm := range resource.Permissions {
				if perm.Type == "Role" && perm.ID == filesReadWriteAllID {
					affectedApps = append(affectedApps, app)
					break
				}
			}
		}
	}

	finding := types.Finding{
		Type:        IDDangerousPermissionFiles,
		Severity:    types.SeverityCritical,
		Category:    string(CategoryDangerousPermissionFiles),
		Title:       "App with Dangerous File Permissions",
		Description: "Applications with Files.ReadWrite.All can access all users' OneDrive and SharePoint files. Limit scope to specific sites or use delegated permissions.",
		Count:       len(affectedApps),
	}

	if data.IncludeDetails && len(affectedApps) > 0 {
		finding.AffectedEntities = helpers.ToAffectedAppEntities(affectedApps)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDangerousPermissionFilesDetector())
}
