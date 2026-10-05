package roles

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// monitoredGroupAssignedRoleIDs is the role set this detector watches for
// group assignment. It is a superset of the shared privilegedRoleIDs
// (permanent-admin-assignments.go): the title "Admin Role Assigned to Group"
// promises coverage of admin roles generally, not just the four privileged
// roles that map tracks for PIM/permanent-assignment purposes. Role IDs are
// Microsoft's own (Microsoft Learn, "Microsoft Entra built-in roles",
// learn.microsoft.com/en-us/entra/identity/role-based-access-control/
// permissions-reference); which roles get group-assigned is a tenant choice
// Microsoft's own best practices explicitly endorse (learn.microsoft.com/
// en-us/entra/identity/role-based-access-control/best-practices, "Use groups
// for Microsoft Entra role assignments").
var monitoredGroupAssignedRoleIDs = map[string]bool{
	types.AzureRoleGlobalAdmin:            true,
	types.AzureRoleSecurityAdmin:          true,
	types.AzureRolePrivilegedRoleAdmin:    true,
	types.AzureRoleUserAdmin:              true,
	types.AzureRoleExchangeAdmin:          true,
	types.AzureRoleSharePointAdmin:        true,
	types.AzureRoleCloudAppAdmin:          true,
	types.AzureRoleAppAdmin:               true,
	types.AzureRoleConditionalAccessAdmin: true,
}

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
		if ra.PrincipalType == "Group" && monitoredGroupAssignedRoleIDs[ra.RoleID] {
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
