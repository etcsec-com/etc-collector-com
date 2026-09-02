package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// EmptyPrivilegedDetector checks for empty privileged groups
type EmptyPrivilegedDetector struct {
	audit.BaseDetector
}

// NewEmptyPrivilegedDetector creates a new detector
func NewEmptyPrivilegedDetector() *EmptyPrivilegedDetector {
	return &EmptyPrivilegedDetector{
		BaseDetector: audit.NewBaseDetector("GROUP_EMPTY_PRIVILEGED", audit.CategoryGroups),
	}
}

var emptyPrivilegedGroups = []string{
	"Domain Admins",
	"Enterprise Admins",
	"Schema Admins",
	"Administrators",
	"Account Operators",
	"Server Operators",
	"Backup Operators",
	"Print Operators",
	"DnsAdmins",
	"Group Policy Creator Owners",
}

// Detect executes the detection
func (d *EmptyPrivilegedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group
	var affectedNames []string

	for _, group := range data.Groups {
		name := group.SAMAccountName
		if name == "" {
			name = group.DisplayName
		}

		// Check if it's a privileged group
		isPrivileged := false
		for _, pg := range emptyPrivilegedGroups {
			if strings.EqualFold(name, pg) || strings.Contains(strings.ToLower(group.DistinguishedName), strings.ToLower("cn="+pg)) {
				isPrivileged = true
				break
			}
		}
		if !isPrivileged {
			continue
		}

		// Check if group is empty
		if len(group.Member) == 0 {
			affected = append(affected, group)
			affectedNames = append(affectedNames, name)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Empty Privileged Group",
		Description: "Privileged groups with no members. While not a vulnerability, empty admin groups may indicate misconfiguration or unused infrastructure.",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
		}
		finding.Details = map[string]interface{}{
			"groups":         affectedNames,
			"recommendation": "Document intentionally empty groups or remove if unused.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewEmptyPrivilegedDetector())
}
