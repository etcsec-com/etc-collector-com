package roles

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

var privilegedRoleIDs = map[string]bool{
	types.AzureRoleGlobalAdmin:         true,
	types.AzureRoleSecurityAdmin:       true,
	types.AzureRolePrivilegedRoleAdmin: true,
	types.AzureRoleUserAdmin:           true,
}

// PermanentAdminAssignmentsDetector checks for permanent admin assignments
type PermanentAdminAssignmentsDetector struct {
	audit.BaseDetector
}

// NewPermanentAdminAssignmentsDetector creates a new detector
func NewPermanentAdminAssignmentsDetector() *PermanentAdminAssignmentsDetector {
	return &PermanentAdminAssignmentsDetector{
		BaseDetector: audit.NewBaseDetector("PA_PERMANENT_ADMIN_ASSIGNMENTS", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *PermanentAdminAssignmentsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var permanentAdminAssignments []types.RoleAssignment

	// Find permanent assignments of privileged roles
	for _, ra := range data.AzureRoleAssignments {
		if ra.IsPermanent && privilegedRoleIDs[ra.RoleID] {
			permanentAdminAssignments = append(permanentAdminAssignments, ra)
		}
	}

	count := len(permanentAdminAssignments)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Permanent Administrative Role Assignments",
		Description: fmt.Sprintf("Administrative roles are permanently assigned instead of using time-limited PIM eligible assignments. Found %d permanent administrative assignments. Use PIM to provide just-in-time access.", count),
		Count:       count,
	}

	if count > 0 {
		finding.AffectedEntities = helpers.ToAffectedRoleAssignmentEntities(permanentAdminAssignments)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPermanentAdminAssignmentsDetector())
}
