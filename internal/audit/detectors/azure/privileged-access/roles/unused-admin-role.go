package roles

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// UnusedAdminRoleDetector checks for enabled directory role templates that
// currently have zero assignments.
//
// This is a different measurement from Microsoft's own "unused" guidance.
// Microsoft's documented recommendation (Microsoft Learn, "Best practices for
// Microsoft Entra roles", learn.microsoft.com/en-us/entra/identity/
// role-based-access-control/best-practices, best practice #4 "Configure
// recurring access reviews to revoke unneeded permissions over time") is
// about reviewing and removing individual role ASSIGNMENTS a holder no longer
// needs - it says nothing about role definitions with no current holders at
// all. This detector measures the latter (an attack-surface/hygiene signal:
// enabled role templates nobody currently holds), which is an etc-collector
// check, not the access-review recommendation Microsoft documents.
type UnusedAdminRoleDetector struct {
	audit.BaseDetector
}

// NewUnusedAdminRoleDetector creates a new detector
func NewUnusedAdminRoleDetector() *UnusedAdminRoleDetector {
	return &UnusedAdminRoleDetector{
		BaseDetector: audit.NewBaseDetector("PA_UNUSED_ADMIN_ROLE", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *UnusedAdminRoleDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Build set of role IDs that have assignments
	assignedRoleIDs := make(map[string]bool)
	for _, ra := range data.AzureRoleAssignments {
		assignedRoleIDs[ra.RoleID] = true
	}

	// Find directory roles with no assignments
	var unusedRoles []types.DirectoryRole
	for _, role := range data.AzureDirectoryRoles {
		if role.IsEnabled && !assignedRoleIDs[role.RoleTemplateID] {
			unusedRoles = append(unusedRoles, role)
		}
	}

	count := len(unusedRoles)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Enabled Administrative Roles With No Current Assignments",
		Description: fmt.Sprintf("Enabled directory roles that currently have zero assignments. Found %d such roles. This is distinct from Microsoft's access-review guidance on removing individual assignments a holder no longer needs - review whether these role definitions are needed at all.", count),
		Count:       count,
	}

	if count > 0 {
		entities := make([]types.AffectedEntity, len(unusedRoles))
		for i, role := range unusedRoles {
			entities[i] = types.AffectedEntity{
				Type:        "directoryRole",
				DN:          role.ID,
				Name:        role.DisplayName,
				Description: fmt.Sprintf("Role Template ID: %s", role.RoleTemplateID),
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUnusedAdminRoleDetector())
}
