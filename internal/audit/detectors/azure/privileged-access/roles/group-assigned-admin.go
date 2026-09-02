package roles

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GroupAssignedAdminDetector checks for admin roles assigned to groups
type GroupAssignedAdminDetector struct {
	audit.BaseDetector
}

// NewGroupAssignedAdminDetector creates a new detector
func NewGroupAssignedAdminDetector() *GroupAssignedAdminDetector {
	return &GroupAssignedAdminDetector{
		BaseDetector: audit.NewBaseDetector("PA_GROUP_ASSIGNED_ADMIN", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *GroupAssignedAdminDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var groupAdminAssignments []types.RoleAssignment

	// Find groups with administrative role assignments
	for _, ra := range data.AzureRoleAssignments {
		if ra.PrincipalType == "Group" && privilegedRoleIDs[ra.RoleID] {
			groupAdminAssignments = append(groupAdminAssignments, ra)
		}
	}

	count := len(groupAdminAssignments)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Admin Role Assigned to Group",
		Description: fmt.Sprintf("Administrative roles are assigned to groups. Found %d group admin assignments. Ensure group membership is tightly controlled and audited regularly.", count),
		Count:       count,
	}

	if count > 0 {
		finding.AffectedEntities = helpers.ToAffectedRoleAssignmentEntities(groupAdminAssignments)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewGroupAssignedAdminDetector())
}
