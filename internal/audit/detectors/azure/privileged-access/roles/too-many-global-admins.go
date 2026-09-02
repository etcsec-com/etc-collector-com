package roles

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TooManyGlobalAdminsDetector checks for excessive Global Administrator assignments
type TooManyGlobalAdminsDetector struct {
	audit.BaseDetector
}

// NewTooManyGlobalAdminsDetector creates a new detector
func NewTooManyGlobalAdminsDetector() *TooManyGlobalAdminsDetector {
	return &TooManyGlobalAdminsDetector{
		BaseDetector: audit.NewBaseDetector("PA_TOO_MANY_GLOBAL_ADMINS", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *TooManyGlobalAdminsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var globalAdminAssignments []types.RoleAssignment

	// Count Global Administrator role assignments
	for _, ra := range data.AzureRoleAssignments {
		if ra.RoleID == types.AzureRoleGlobalAdmin {
			globalAdminAssignments = append(globalAdminAssignments, ra)
		}
	}

	count := 0
	if len(globalAdminAssignments) > 5 {
		count = len(globalAdminAssignments)
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Too Many Global Administrators",
		Description: fmt.Sprintf("More than 5 users have Global Administrator role (%d found). Microsoft recommends fewer than 5 to minimize security risk.", len(globalAdminAssignments)),
		Count:       count,
	}

	if count > 0 {
		finding.AffectedEntities = helpers.ToAffectedRoleAssignmentEntities(globalAdminAssignments)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewTooManyGlobalAdminsDetector())
}
