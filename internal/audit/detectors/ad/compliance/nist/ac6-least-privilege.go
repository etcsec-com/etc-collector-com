package nist

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AC6LeastPrivilegeDetector checks NIST AC-6 least privilege compliance
type AC6LeastPrivilegeDetector struct {
	audit.BaseDetector
}

// NewAC6LeastPrivilegeDetector creates a new detector
func NewAC6LeastPrivilegeDetector() *AC6LeastPrivilegeDetector {
	return &AC6LeastPrivilegeDetector{
		BaseDetector: audit.NewBaseDetector("NIST_AC_6_LEAST_PRIVILEGE", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *AC6LeastPrivilegeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string

	// AC-6(1): Authorize access to security functions
	// Check for users in multiple highly privileged groups
	//
	// Server Operators and Backup Operators are domain-local Builtin groups:
	// a special principal (Everyone/Authenticated Users) can be a member of
	// either without that membership EVER appearing in any real user's
	// memberOf (Windows computes it at logon, it never writes a back-link on
	// a user object). Without this, the loop below is structurally blind to
	// that case no matter the real state of the domain (T_127 confrontation).
	serverOpsOpenToAll := groupOpenToSpecialPrincipal(data.Groups, "server operators")
	backupOpsOpenToAll := groupOpenToSpecialPrincipal(data.Groups, "backup operators")

	usersInMultiplePrivGroups := 0
	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}
		privGroupCount := 0
		hasServerOps := serverOpsOpenToAll
		hasBackupOps := backupOpsOpenToAll
		for _, memberOf := range u.MemberOf {
			memberOfLower := strings.ToLower(memberOf)
			if strings.Contains(memberOfLower, "domain admins") ||
				strings.Contains(memberOfLower, "enterprise admins") ||
				strings.Contains(memberOfLower, "schema admins") ||
				strings.Contains(memberOfLower, "account operators") {
				privGroupCount++
			}
			if strings.Contains(memberOfLower, "server operators") {
				hasServerOps = true
			}
			if strings.Contains(memberOfLower, "backup operators") {
				hasBackupOps = true
			}
		}
		if hasServerOps {
			privGroupCount++
		}
		if hasBackupOps {
			privGroupCount++
		}
		if privGroupCount > 1 {
			usersInMultiplePrivGroups++
		}
	}

	if usersInMultiplePrivGroups > 0 {
		issues = append(issues, "AC-6(1): Users in multiple privileged groups")
	}

	// AC-6(5): Privileged accounts - excessive domain admins
	daCount := 0
	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}
		for _, memberOf := range u.MemberOf {
			if strings.Contains(strings.ToLower(memberOf), "domain admins") {
				daCount++
				break
			}
		}
	}

	if daCount > 5 {
		issues = append(issues, "AC-6(5): Excessive Domain Admin accounts")
	}

	// AC-6(10): Prohibit non-privileged users from executing privileged functions
	// Check for regular users with adminCount set
	regularUsersWithAdmin := 0
	for _, u := range data.Users {
		if u.Enabled() && u.AdminCount && len(u.ServicePrincipalNames) == 0 {
			isInPrivGroup := false
			for _, memberOf := range u.MemberOf {
				if strings.Contains(strings.ToLower(memberOf), "domain admins") ||
					strings.Contains(strings.ToLower(memberOf), "enterprise admins") {
					isInPrivGroup = true
					break
				}
			}
			if !isInPrivGroup {
				regularUsersWithAdmin++
			}
		}
	}

	if regularUsersWithAdmin > 10 {
		issues = append(issues, "AC-6(10): Many accounts with adminCount outside standard admin groups")
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "NIST AC-6 Least Privilege Non-Compliant",
		Description: "Least privilege principles not fully implemented per NIST SP 800-53 AC-6 requirements.",
		Count:       0,
		Details: map[string]interface{}{
			"framework":                  "NIST",
			"control":                    "AC-6",
			"publication":                "SP 800-53",
			"domainAdmins":               daCount,
			"usersInMultiplePrivGroups":  usersInMultiplePrivGroups,
			"regularUsersWithAdminCount": regularUsersWithAdmin,
		},
	}

	if len(issues) > 0 {
		finding.Count = 1
		finding.Details["violations"] = issues
	}

	return []types.Finding{finding}
}

// groupOpenToSpecialPrincipal reports whether the group named groupName
// (matched case-insensitively against SAMAccountName/CN) has Everyone
// (S-1-1-0) or Authenticated Users (S-1-5-11) as a raw LDAP member — the
// same match used by GROUP_EVERYONE_IN_PRIVILEGED / GROUP_AUTHENTICATED_
// USERS_PRIVILEGED (groups/privileged package) to spot this exact pattern.
func groupOpenToSpecialPrincipal(groups []types.Group, groupName string) bool {
	for _, g := range groups {
		name := g.SAMAccountName
		if name == "" {
			name = g.CN
		}
		if !strings.EqualFold(name, groupName) {
			continue
		}
		for _, m := range g.Members {
			ml := strings.ToLower(m)
			if strings.Contains(ml, "everyone") || strings.Contains(m, "S-1-1-0") ||
				strings.Contains(ml, "authenticated users") || strings.Contains(m, "S-1-5-11") {
				return true
			}
		}
	}
	return false
}

func init() {
	audit.MustRegister(NewAC6LeastPrivilegeDetector())
}
