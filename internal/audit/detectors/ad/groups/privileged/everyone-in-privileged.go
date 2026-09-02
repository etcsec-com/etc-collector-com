package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// EveryoneInPrivilegedDetector checks for Everyone group in privileged groups
type EveryoneInPrivilegedDetector struct {
	audit.BaseDetector
}

// NewEveryoneInPrivilegedDetector creates a new detector
func NewEveryoneInPrivilegedDetector() *EveryoneInPrivilegedDetector {
	return &EveryoneInPrivilegedDetector{
		BaseDetector: audit.NewBaseDetector("GROUP_EVERYONE_IN_PRIVILEGED", audit.CategoryGroups),
	}
}

var privilegedGroupsEveryone = []string{
	"Domain Admins",
	"Enterprise Admins",
	"Schema Admins",
	"Administrators",
	"Account Operators",
	"Server Operators",
	"Backup Operators",
	"Print Operators",
}

// Detect executes the detection
func (d *EveryoneInPrivilegedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group

	for _, group := range data.Groups {
		groupName := group.SAMAccountName
		if groupName == "" {
			groupName = group.CN
		}

		// Check if it's a privileged group
		isPrivileged := false
		for _, pg := range privilegedGroupsEveryone {
			if strings.EqualFold(groupName, pg) {
				isPrivileged = true
				break
			}
		}
		if !isPrivileged || len(group.Member) == 0 {
			continue
		}

		// Check if Everyone (S-1-1-0) or World is a member
		for _, member := range group.Member {
			memberLower := strings.ToLower(member)
			if strings.Contains(memberLower, "everyone") ||
				strings.Contains(member, "S-1-1-0") ||
				strings.Contains(memberLower, "world") {
				affected = append(affected, group)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Everyone in Privileged Group",
		Description: "The Everyone principal is a member of a privileged group. This grants ALL users (including anonymous) administrative privileges.",
		Count:       len(affected),
		Details: map[string]interface{}{
			"recommendation": "Immediately remove Everyone from privileged groups.",
			"risk":           "Complete domain compromise - anyone can authenticate as admin.",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewEveryoneInPrivilegedDetector())
}
