package roles

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CustomRoleExcessiveDetector checks for excessive custom directory roles
type CustomRoleExcessiveDetector struct {
	audit.BaseDetector
}

// NewCustomRoleExcessiveDetector creates a new detector
func NewCustomRoleExcessiveDetector() *CustomRoleExcessiveDetector {
	return &CustomRoleExcessiveDetector{
		BaseDetector: audit.NewBaseDetector("PA_CUSTOM_ROLE_EXCESSIVE", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *CustomRoleExcessiveDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var customRoles []types.DirectoryRole
	const excessiveThreshold = 10

	// Count custom directory roles
	for _, role := range data.AzureDirectoryRoles {
		if !role.IsBuiltIn {
			customRoles = append(customRoles, role)
		}
	}

	count := 0
	if len(customRoles) > excessiveThreshold {
		count = len(customRoles)
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Excessive Custom Directory Roles",
		Description: fmt.Sprintf("Many custom directory roles defined (%d found). Custom roles add complexity and may have overly broad permissions. Review and consolidate where possible.", len(customRoles)),
		Count:       count,
	}

	if count > 0 {
		entities := make([]types.AffectedEntity, len(customRoles))
		for i, role := range customRoles {
			entities[i] = types.AffectedEntity{
				Type:        "directoryRole",
				DN:          role.ID,
				Name:        role.DisplayName,
				Description: fmt.Sprintf("Custom role - Template ID: %s", role.RoleTemplateID),
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCustomRoleExcessiveDetector())
}
