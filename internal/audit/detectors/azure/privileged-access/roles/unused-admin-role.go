package roles

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// UnusedAdminRoleDetector checks for active directory roles with no assignments
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
		Title:       "Unused Administrative Roles",
		Description: fmt.Sprintf("Active directory roles with no assignments. Found %d unused roles. Review if these roles are needed or can be disabled to reduce attack surface.", count),
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
