package roles

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ServicePrincipalAdminDetector checks for service principals with admin roles
type ServicePrincipalAdminDetector struct {
	audit.BaseDetector
}

// NewServicePrincipalAdminDetector creates a new detector
func NewServicePrincipalAdminDetector() *ServicePrincipalAdminDetector {
	return &ServicePrincipalAdminDetector{
		BaseDetector: audit.NewBaseDetector("PA_SERVICE_PRINCIPAL_ADMIN", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *ServicePrincipalAdminDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var spAdminAssignments []types.RoleAssignment

	// Find service principals with privileged roles
	for _, ra := range data.AzureRoleAssignments {
		if ra.PrincipalType == "ServicePrincipal" && privilegedRoleIDs[ra.RoleID] {
			spAdminAssignments = append(spAdminAssignments, ra)
		}
	}

	count := len(spAdminAssignments)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Service Principal with Admin Role",
		Description: fmt.Sprintf("Service principals have administrative directory roles. Found %d service principal admin assignments. Compromised service principals provide persistent admin access and cannot use MFA.", count),
		Count:       count,
	}

	if count > 0 {
		finding.AffectedEntities = helpers.ToAffectedRoleAssignmentEntities(spAdminAssignments)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewServicePrincipalAdminDetector())
}
