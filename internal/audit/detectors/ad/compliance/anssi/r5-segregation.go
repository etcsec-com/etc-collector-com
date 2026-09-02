package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R5SegregationDetector checks ANSSI R5 segregation compliance
type R5SegregationDetector struct {
	audit.BaseDetector
}

// NewR5SegregationDetector creates a new detector
func NewR5SegregationDetector() *R5SegregationDetector {
	return &R5SegregationDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R5_SEGREGATION", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *R5SegregationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string

	// Backup Operators is a domain-local Builtin group: a special principal
	// (Everyone/Authenticated Users) can be a member of it without that
	// membership EVER appearing in any real user's memberOf (Windows
	// computes it at logon, it never writes a back-link on a user object).
	// Without this, the loop below is structurally blind to that case no
	// matter the real state of the domain (T_127, R5/NIST_AC_6 confrontation).
	backupOpsOpenToAll := groupOpenToSpecialPrincipal(data.Groups, "backup operators")

	// Check for users in multiple privileged groups (no segregation)
	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}

		privilegedGroupCount := 0
		hasBackupOps := backupOpsOpenToAll
		for _, memberOf := range u.MemberOf {
			memberOfLower := strings.ToLower(memberOf)
			if strings.Contains(memberOfLower, "domain admins") ||
				strings.Contains(memberOfLower, "enterprise admins") ||
				strings.Contains(memberOfLower, "schema admins") ||
				strings.Contains(memberOfLower, "account operators") {
				privilegedGroupCount++
			}
			if strings.Contains(memberOfLower, "backup operators") {
				hasBackupOps = true
			}
		}
		if hasBackupOps {
			privilegedGroupCount++
		}

		if privilegedGroupCount > 1 {
			issues = append(issues, "Users in multiple privileged groups (no segregation)")
			break
		}
	}

	// Check if standard users have admin access
	standardUsersWithAdmin := 0
	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}
		hasServiceSPN := len(u.ServicePrincipalNames) > 0
		isAdmin := u.AdminCount

		if !hasServiceSPN && isAdmin {
			standardUsersWithAdmin++
		}
	}

	if standardUsersWithAdmin > 20 {
		issues = append(issues, "Many standard users with admin privileges")
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ANSSI R5 - Segregation Non-Compliant",
		Description: "Privilege segregation does not meet ANSSI R5 recommendations. Separate admin roles and minimize privilege overlap.",
		Count:       0,
	}

	if len(issues) > 0 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"violations":             issues,
			"framework":              "ANSSI",
			"control":                "R5",
			"standardUsersWithAdmin": standardUsersWithAdmin,
		}
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
	audit.MustRegister(NewR5SegregationDetector())
}
