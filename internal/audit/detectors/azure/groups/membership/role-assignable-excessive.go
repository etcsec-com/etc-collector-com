package membership

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// RoleAssignableDetector checks for role-assignable groups
type RoleAssignableDetector struct {
	audit.BaseDetector
}

// NewRoleAssignableDetector creates a new detector
func NewRoleAssignableDetector() *RoleAssignableDetector {
	return &RoleAssignableDetector{
		BaseDetector: audit.NewBaseDetector("AZ_GROUP_ROLE_ASSIGNABLE", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *RoleAssignableDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group

	// AdminCount == true is used as proxy for role-assignable in Azure context
	for _, group := range data.Groups {
		if group.AdminCount {
			affected = append(affected, group)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Role-Assignable Groups",
		Description: "Groups that can be assigned to directory roles require careful membership control.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewRoleAssignableDetector())
}
