package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// T_075 — NO_PROTECTED_USERS_MONITORING (monitoring/protected-users.go) lived
// alongside this detector with the same claim ("privileged account missing
// from Protected Users"), a plain adminCount-only eligibility test and no
// exclusions. On DC01 it produced this detector's exact 4 accounts plus 3
// more (the built-in Administrator, and two SPN-bearing service accounts)
// that CANNOT be added to Protected Users without breaking authentication or
// Kerberos delegation — its extra "findings" were false positives this
// detector's exclusions (below) exist specifically to prevent. Removed; it
// carried no compliance mapping, so removing it costs nothing (dedup.go, R4).
// See detectors/ad/dedup.go.

// NotInProtectedUsersDetector detects privileged accounts not in Protected Users group
type NotInProtectedUsersDetector struct {
	audit.BaseDetector
}

// NewNotInProtectedUsersDetector creates a new detector
func NewNotInProtectedUsersDetector() *NotInProtectedUsersDetector {
	return &NotInProtectedUsersDetector{
		BaseDetector: audit.NewBaseDetector("NOT_IN_PROTECTED_USERS", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *NotInProtectedUsersDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	// Find Protected Users group
	var protectedUsersGroup *types.Group
	for i := range data.Groups {
		name := data.Groups[i].SAMAccountName
		if name == "" {
			name = data.Groups[i].CN
		}
		if strings.EqualFold(name, "protected users") {
			protectedUsersGroup = &data.Groups[i]
			break
		}
	}

	// If Protected Users doesn't exist (pre-2012R2), skip
	if protectedUsersGroup == nil {
		return []types.Finding{}
	}

	for _, u := range data.Users {
		if u.Disabled {
			continue
		}

		// Check if privileged
		isPrivileged := false

		// Criterion 1: AdminCount=true
		if u.AdminCount {
			isPrivileged = true
		}

		// Criterion 2: Member of privileged groups
		if !isPrivileged && len(u.MemberOf) > 0 {
			privilegedGroups := []string{
				"Domain Admins", "Enterprise Admins", "Schema Admins",
				"Administrators", "Account Operators", "Backup Operators",
				"Server Operators",
			}
			isPrivileged = helpers.IsInAnyGroup(u.MemberOf, privilegedGroups)
		}

		if !isPrivileged {
			continue
		}

		// Exclusions
		if strings.EqualFold(u.SAMAccountName, "krbtgt") {
			continue
		}
		if strings.EqualFold(u.SAMAccountName, "administrator") {
			continue
		}
		if len(u.ServicePrincipalNames) > 0 {
			continue // Service accounts incompatible with Protected Users
		}

		// Check if in Protected Users (both methods)
		isInProtectedUsers := false

		// Method 1: Check user's MemberOf
		for _, dn := range u.MemberOf {
			if strings.Contains(strings.ToLower(dn), "cn=protected users") {
				isInProtectedUsers = true
				break
			}
		}

		// Method 2: Check group's member list
		if !isInProtectedUsers && protectedUsersGroup != nil {
			for _, memberDN := range protectedUsersGroup.Member {
				if strings.EqualFold(memberDN, u.DN) {
					isInProtectedUsers = true
					break
				}
			}
		}

		if !isInProtectedUsers {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Privileged Accounts Not in Protected Users",
		Description: "Privileged accounts not in Protected Users group. Missing enhanced security protections (NTLM disabled, no Kerberos delegation, no credential caching).",
		Count:       len(affected),
		Details: map[string]interface{}{
			"recommendation": "Add privileged accounts to Protected Users group",
			"exclusions":     "Service accounts with SPNs excluded (incompatible)",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNotInProtectedUsersDetector())
}
