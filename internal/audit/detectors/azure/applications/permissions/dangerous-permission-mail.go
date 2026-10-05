package permissions

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDDangerousPermissionMail       = "APP_DANGEROUS_PERMISSION_MAIL"
	CategoryDangerousPermissionMail = audit.CategoryApplications
)

type DangerousPermissionMailDetector struct {
	audit.BaseDetector
}

func NewDangerousPermissionMailDetector() *DangerousPermissionMailDetector {
	return &DangerousPermissionMailDetector{
		BaseDetector: audit.NewBaseDetector(IDDangerousPermissionMail, CategoryDangerousPermissionMail),
	}
}

func (d *DangerousPermissionMailDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedApps []types.AppRegistration

	// Dangerous mail permissions
	mailReadWriteID := types.DangerousGraphPermissions["Mail.ReadWrite"]
	mailReadID := types.DangerousGraphPermissions["Mail.Read"]

	for _, app := range data.AzureAppRegistrations {
		for _, resource := range app.RequiredResourceAccess {
			if resource.ResourceAppID != types.MicrosoftGraphAppID {
				continue
			}

			for _, perm := range resource.Permissions {
				if perm.Type == "Role" && (perm.ID == mailReadWriteID || perm.ID == mailReadID) {
					affectedApps = append(affectedApps, app)
					break
				}
			}
		}
	}

	finding := types.Finding{
		Type:        IDDangerousPermissionMail,
		Severity:    types.SeverityCritical,
		Category:    string(CategoryDangerousPermissionMail),
		Title:       "App with Dangerous Mail Permissions",
		Description: "Applications with Mail.ReadWrite or Mail.Read application permissions can access all mailboxes. Review these applications and use delegated permissions instead of application permissions where possible.",
		Count:       len(affectedApps),
	}

	if data.IncludeDetails && len(affectedApps) > 0 {
		finding.AffectedEntities = helpers.ToAffectedAppEntities(affectedApps)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDangerousPermissionMailDetector())
}
