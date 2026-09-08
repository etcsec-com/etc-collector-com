package roles

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminNoCAPolicyDetector checks for CA policies targeting admin roles
//
// Microsoft documents two valid patterns for protecting admin roles with
// Conditional Access, either of which satisfies the recommendation:
//  1. A policy scoped to Directory roles (Microsoft Learn, "Require MFA for
//     administrators with Conditional Access", learn.microsoft.com/en-us/entra/
//     identity/conditional-access/policy-old-require-mfa-admin).
//  2. The baseline policy scoped to All users with the MFA grant control
//     (Microsoft Learn, "Require MFA for all users with Conditional Access",
//     learn.microsoft.com/en-us/entra/identity/conditional-access/
//     policy-all-users-mfa-strength) - admins are users too, so this covers
//     them as well.
type AdminNoCAPolicyDetector struct {
	audit.BaseDetector
}

// NewAdminNoCAPolicyDetector creates a new detector
func NewAdminNoCAPolicyDetector() *AdminNoCAPolicyDetector {
	return &AdminNoCAPolicyDetector{
		BaseDetector: audit.NewBaseDetector("PA_ADMIN_NO_CA_POLICY", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *AdminNoCAPolicyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasPolicyForAdminRoles := false

	// Check if any enabled CA policy targets admin directory roles, or
	// applies the all-users MFA baseline that covers admins too.
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}
		if len(policy.IncludeRoles) > 0 {
			hasPolicyForAdminRoles = true
			break
		}
		if includesAllUsers(policy.IncludeUsers) && requiresMFA(policy.GrantControls) {
			hasPolicyForAdminRoles = true
			break
		}
	}

	count := 0
	if !hasPolicyForAdminRoles {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "No CA Policy for Administrative Roles",
		Description: "No Conditional Access policy targets admin directory roles, and no all-users MFA baseline policy covers them either. Administrative roles should be protected by CA policies requiring MFA, compliant devices, and other security controls.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminNoCAPolicyDetector())
}

// includesAllUsers reports whether a CA policy's user condition targets All users.
func includesAllUsers(includeUsers []string) bool {
	for _, u := range includeUsers {
		if u == "All" {
			return true
		}
	}
	return false
}

// requiresMFA reports whether a CA policy's grant controls include the mfa control.
func requiresMFA(grantControls []string) bool {
	for _, gc := range grantControls {
		if strings.EqualFold(gc, "mfa") {
			return true
		}
	}
	return false
}
