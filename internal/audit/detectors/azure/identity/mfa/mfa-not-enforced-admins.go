package mfa

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	ID       = "MFA_NOT_ENFORCED_ADMINS"
	Category = audit.CategoryIdentity
)

// MfaNotEnforcedAdminsDetector checks if MFA is enforced for administrators
type MfaNotEnforcedAdminsDetector struct {
	audit.BaseDetector
}

// NewMfaNotEnforcedAdminsDetector creates a new MFA not enforced for admins detector
func NewMfaNotEnforcedAdminsDetector() *MfaNotEnforcedAdminsDetector {
	return &MfaNotEnforcedAdminsDetector{
		BaseDetector: audit.NewBaseDetector(ID, Category),
	}
}

// privilegedRoleIDs - the same isPrivileged=true role set used by
// serviceprincipals.SPHighPrivilegeDetector (Global/Privileged Role/App/
// Cloud App/Security/User/Conditional Access Admin), sourced from Microsoft
// Graph's roleDefinition.isPrivileged flag and cross-checked against
// "Privileged roles and permissions in Microsoft Entra ID" (learn.microsoft.
// com/en-us/entra/identity/role-based-access-control/
// privileged-roles-permissions). Exchange and SharePoint Administrator are
// deliberately excluded - Graph does not mark them isPrivileged despite the
// "Administrator" name.
var privilegedRoleIDs = map[string]bool{
	types.AzureRoleGlobalAdmin:            true,
	types.AzureRolePrivilegedRoleAdmin:    true,
	types.AzureRoleAppAdmin:               true,
	types.AzureRoleCloudAppAdmin:          true,
	types.AzureRoleSecurityAdmin:          true,
	types.AzureRoleUserAdmin:              true,
	types.AzureRoleConditionalAccessAdmin: true,
}

// Detect checks if any Conditional Access policy enforces MFA for
// privileged directory roles.
//
// Known limitation (non vu, not fixable in this detector alone):
// ConditionalAccessPolicy.GrantControls only captures grantControls'
// builtInControls (internal/providers/azure/client.go calls
// gc.GetBuiltInControls(), never gc.GetAuthenticationStrength()). A tenant
// enforcing MFA-equivalent protection through an authentication strength
// grant control instead of the classic "mfa" built-in control - Microsoft
// Graph treats these as mutually exclusive grant mechanisms on the same
// policy (learn.microsoft.com/en-us/entra/identity/conditional-access/
// concept-conditional-access-grant) - is invisible to this check and will
// be wrongly reported as "not enforced". Fixing this needs a new field on
// types.ConditionalAccessPolicy and a collector change, both out of this
// detector's scope.
func (d *MfaNotEnforcedAdminsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:     ID,
		Severity: types.SeverityCritical,
		Category: string(Category),
		Title:    "MFA Not Enforced for Administrators",
		Description: "No Conditional Access policy requires MFA for privileged directory roles. " +
			"Administrative accounts without MFA are prime targets for credential attacks. This " +
			"only recognizes the classic 'mfa' grant control; a policy that requires MFA through " +
			"an authentication strength grant control instead is not currently detected (collector " +
			"does not capture authenticationStrength on Conditional Access policies).",
		Count: 0,
	}

	// Check if any enabled CA policy requires MFA for admin roles
	hasMFAForAdmins := false
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}

		// Check if policy targets at least one actually-privileged role -
		// not just "some role, any role" as before, which let a policy
		// targeting an arbitrary non-privileged role (e.g. Helpdesk
		// Administrator) mask a real MFA gap on the privileged roles above.
		targetsAdmins := false
		for _, roleID := range policy.IncludeRoles {
			if privilegedRoleIDs[roleID] {
				targetsAdmins = true
				break
			}
		}

		// Check if policy grants MFA
		requiresMFA := false
		for _, control := range policy.GrantControls {
			if control == "mfa" {
				requiresMFA = true
				break
			}
		}

		if targetsAdmins && requiresMFA {
			hasMFAForAdmins = true
			break
		}
	}

	if !hasMFAForAdmins {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewMfaNotEnforcedAdminsDetector())
}
