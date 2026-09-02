package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AuthenticatedUsersPrivilegedDetector checks for Authenticated Users in privileged groups
type AuthenticatedUsersPrivilegedDetector struct {
	audit.BaseDetector
}

// NewAuthenticatedUsersPrivilegedDetector creates a new detector
func NewAuthenticatedUsersPrivilegedDetector() *AuthenticatedUsersPrivilegedDetector {
	return &AuthenticatedUsersPrivilegedDetector{
		BaseDetector: audit.NewBaseDetector("GROUP_AUTHENTICATED_USERS_PRIVILEGED", audit.CategoryGroups),
	}
}

var privilegedGroupsAuthUsers = []string{
	"Domain Admins",
	"Enterprise Admins",
	"Schema Admins",
	"Administrators",
	"Account Operators",
	"Server Operators",
	"Backup Operators",
}

// Detect executes the detection
func (d *AuthenticatedUsersPrivilegedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group

	for _, group := range data.Groups {
		groupName := group.SAMAccountName
		if groupName == "" {
			groupName = group.CN
		}

		// Check if it's a privileged group
		isPrivileged := false
		for _, pg := range privilegedGroupsAuthUsers {
			if strings.EqualFold(groupName, pg) {
				isPrivileged = true
				break
			}
		}
		if !isPrivileged || len(group.Member) == 0 {
			continue
		}

		// Check if Authenticated Users (S-1-5-11) is a member
		for _, member := range group.Member {
			memberLower := strings.ToLower(member)
			if strings.Contains(memberLower, "authenticated users") ||
				strings.Contains(member, "S-1-5-11") ||
				strings.Contains(memberLower, "utilisateurs authentifiés") {
				affected = append(affected, group)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Authenticated Users in Privileged Group",
		Description: "Authenticated Users principal is a member of a privileged group. This grants ALL authenticated domain users administrative privileges.",
		Count:       len(affected),
		Details: map[string]interface{}{
			"recommendation": "Remove Authenticated Users from privileged groups immediately.",
			"risk":           "Any domain user can perform administrative actions.",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAuthenticatedUsersPrivilegedDetector())
}
