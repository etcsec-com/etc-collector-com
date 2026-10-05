package emergency

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoEmergencyAccountsDetector checks for break-glass account patterns.
//
// Microsoft's documented pattern (Microsoft Learn, "Manage emergency access
// admin accounts", learn.microsoft.com/en-us/entra/identity/role-based-access-control/
// security-emergency-access, "Create emergency access accounts" and "Security
// guardrails summary") is specific: at least two cloud-only accounts with a
// PERMANENT (not PIM-eligible) Global Administrator assignment, excluded from
// Conditional Access policies that block or restrict sign-in. Checking for
// "any enabled all-users policy with any exclusion" - the previous logic -
// is satisfied by excluding a service account or any other principal for an
// unrelated reason, which masks a tenant that has no real break-glass
// accounts at all. This now looks for the actual documented pattern.
type NoEmergencyAccountsDetector struct {
	audit.BaseDetector
}

// NewNoEmergencyAccountsDetector creates a new detector
func NewNoEmergencyAccountsDetector() *NoEmergencyAccountsDetector {
	return &NoEmergencyAccountsDetector{
		BaseDetector: audit.NewBaseDetector("PA_NO_EMERGENCY_ACCOUNTS", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *NoEmergencyAccountsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Permanent (non-eligible) Global Administrator assignees are candidate
	// emergency access accounts per Microsoft's documented pattern.
	permanentGlobalAdmins := make(map[string]bool)
	for _, ra := range data.AzureRoleAssignments {
		if ra.RoleID == types.AzureRoleGlobalAdmin && ra.IsPermanent {
			permanentGlobalAdmins[ra.PrincipalID] = true
		}
	}

	// Of those, count how many are excluded from at least one enabled CA
	// policy that targets all users - i.e. protected from being locked out
	// by a policy that would otherwise block or restrict their sign-in.
	excludedCandidates := make(map[string]bool)
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State != "enabled" || !includesAllUsers(policy.IncludeUsers) {
			continue
		}
		for _, excluded := range policy.ExcludeUsers {
			if permanentGlobalAdmins[excluded] {
				excludedCandidates[excluded] = true
			}
		}
	}

	// Microsoft recommends two or more emergency access accounts.
	count := 0
	if len(excludedCandidates) < 2 {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "No Emergency Access Accounts Detected",
		Description: "No break-glass/emergency access accounts found: fewer than two accounts hold a permanent Global Administrator assignment and are excluded from all-users Conditional Access policies. Emergency accounts prevent lockout during CA policy misconfigurations or Azure AD outages. Create 2+ cloud-only accounts, permanently assigned Global Administrator, and exclude them from CA policies that block or restrict sign-in.",
		Count:       count,
	}

	return []types.Finding{finding}
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

func init() {
	audit.MustRegister(NewNoEmergencyAccountsDetector())
}
