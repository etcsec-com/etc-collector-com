package serviceprincipals

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDSPHighPrivilege       = "SP_HIGH_PRIVILEGE"
	CategorySPHighPrivilege = audit.CategoryApplications
)

type SPHighPrivilegeDetector struct {
	audit.BaseDetector
}

func NewSPHighPrivilegeDetector() *SPHighPrivilegeDetector {
	return &SPHighPrivilegeDetector{
		BaseDetector: audit.NewBaseDetector(IDSPHighPrivilege, CategorySPHighPrivilege),
	}
}

func (d *SPHighPrivilegeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedSPs []types.ServicePrincipal

	// Build map of service principals by ID for lookup
	spByID := make(map[string]types.ServicePrincipal)
	for _, sp := range data.AzureServicePrincipals {
		spByID[sp.ID] = sp
	}

	// Privileged role IDs
	privilegedRoles := map[string]bool{
		types.AzureRoleGlobalAdmin:         true,
		types.AzureRolePrivilegedRoleAdmin: true,
		types.AzureRoleAppAdmin:            true,
		types.AzureRoleCloudAppAdmin:       true,
	}

	// Track unique service principals
	seenSPs := make(map[string]bool)

	// Check role assignments for service principals with privileged roles
	for _, assignment := range data.AzureRoleAssignments {
		if assignment.PrincipalType == "ServicePrincipal" && privilegedRoles[assignment.RoleID] {
			if sp, exists := spByID[assignment.PrincipalID]; exists {
				if !seenSPs[sp.ID] {
					seenSPs[sp.ID] = true
					affectedSPs = append(affectedSPs, sp)
				}
			}
		}
	}

	finding := types.Finding{
		Type:        IDSPHighPrivilege,
		Severity:    types.SeverityHigh,
		Category:    string(CategorySPHighPrivilege),
		Title:       "Service Principals with High Privilege Roles",
		Description: "Service principals assigned privileged directory roles. Use managed identities and apply least privilege.",
		Count:       len(affectedSPs),
	}

	if data.IncludeDetails && len(affectedSPs) > 0 {
		finding.AffectedEntities = helpers.ToAffectedServicePrincipalEntities(affectedSPs)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSPHighPrivilegeDetector())
}
