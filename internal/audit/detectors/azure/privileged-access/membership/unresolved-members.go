package membership

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// UnresolvedPrivilegedMembersDetector flags members assigned to privileged Entra
// roles whose principal object cannot be resolved (PrincipalName and
// UserPrincipalName both empty after the Graph $expand=principal enrichment).
// These usually indicate stale PIM assignments, deleted users still holding a
// role, or on-premises objects that never synced. Matches Purple Knight SI000123.
type UnresolvedPrivilegedMembersDetector struct {
	audit.BaseDetector
}

func NewUnresolvedPrivilegedMembersDetector() *UnresolvedPrivilegedMembersDetector {
	return &UnresolvedPrivilegedMembersDetector{
		BaseDetector: audit.NewBaseDetector("UNRESOLVED_PRIVILEGED_MEMBERS", audit.CategoryPrivilegedAccess),
	}
}

// privilegedRoles is the set of roles whose unresolved assignments are considered critical.
var privilegedRoles = map[string]string{
	types.AzureRoleGlobalAdmin:         "Global Administrator",
	types.AzureRolePrivilegedRoleAdmin: "Privileged Role Administrator",
	types.AzureRoleSecurityAdmin:       "Security Administrator",
	types.AzureRoleExchangeAdmin:       "Exchange Administrator",
	types.AzureRoleSharePointAdmin:     "SharePoint Administrator",
	types.AzureRoleUserAdmin:           "User Administrator",
	types.AzureRoleAppAdmin:            "Application Administrator",
	types.AzureRoleCloudAppAdmin:       "Cloud Application Administrator",
}

func (d *UnresolvedPrivilegedMembersDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.RoleAssignment
	pairs := make([]string, 0)

	for i := range data.AzureRoleAssignments {
		ra := &data.AzureRoleAssignments[i]
		roleName, isPriv := privilegedRoles[ra.RoleID]
		if !isPriv {
			continue
		}
		// A role assignment is considered unresolved when Graph could not populate
		// the principal display name / UPN via $expand=principal. These show up in
		// raw API output as empty strings despite a valid principalId.
		if ra.PrincipalName == "" && ra.UserPrincipalName == "" && ra.Mail == "" {
			affected = append(affected, *ra)
			pairs = append(pairs, fmt.Sprintf("role=%s principalId=%s", roleName, ra.PrincipalID))
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityHigh,
		Category: string(d.Category()),
		Title:    "Privileged role assignment references an unresolved principal",
		Description: "One or more privileged role assignments reference a principal whose object " +
			"could not be resolved (empty displayName, UPN, and mail after Graph enrichment). " +
			"This often indicates stale assignments, deleted users still holding privileged roles, " +
			"or hybrid identities that failed to sync from on-premises.",
		Count: len(affected),
		Details: map[string]interface{}{
			"recommendation": "Audit each unresolved assignment. Remove stale entries from PIM or directly from the role.",
			"pairs":          pairs,
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.RoleAssignmentsToAffectedEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUnresolvedPrivilegedMembersDetector())
}
