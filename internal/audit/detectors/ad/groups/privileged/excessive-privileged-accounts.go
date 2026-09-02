package privileged

import (
	"context"
	"sort"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ExcessivePrivilegedAccountsDetector checks for too many accounts in high-privilege groups
type ExcessivePrivilegedAccountsDetector struct {
	audit.BaseDetector
}

// NewExcessivePrivilegedAccountsDetector creates a new detector
func NewExcessivePrivilegedAccountsDetector() *ExcessivePrivilegedAccountsDetector {
	return &ExcessivePrivilegedAccountsDetector{
		BaseDetector: audit.NewBaseDetector("EXCESSIVE_PRIVILEGED_ACCOUNTS", audit.CategoryGroups),
	}
}

var privilegedGroupNames = []string{
	"Domain Admins",
	"Enterprise Admins",
	"Schema Admins",
	"Administrators",
	"Account Operators",
	"Backup Operators",
	"Server Operators",
	"Print Operators",
}

// Detect executes the detection
func (d *ExcessivePrivilegedAccountsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Count unique privileged users
	privilegedUsers := make(map[string]bool)
	groupCounts := make(map[string]int)

	for _, user := range data.Users {
		for _, groupDN := range user.MemberOf {
			groupDNUpper := strings.ToUpper(groupDN)
			for _, groupName := range privilegedGroupNames {
				if strings.Contains(groupDNUpper, "CN="+strings.ToUpper(groupName)) {
					privilegedUsers[user.DN] = true
					groupCounts[groupName]++
				}
			}
		}
	}

	// Also count from group membership directly
	for _, group := range data.Groups {
		for _, name := range privilegedGroupNames {
			if strings.EqualFold(group.SAMAccountName, name) ||
				strings.Contains(strings.ToUpper(group.DistinguishedName), "CN="+strings.ToUpper(name)) {
				if len(group.Member) > groupCounts[name] {
					groupCounts[name] = len(group.Member)
				}
			}
		}
	}

	totalPrivileged := len(privilegedUsers)
	domainAdmins := groupCounts["Domain Admins"]
	enterpriseAdmins := groupCounts["Enterprise Admins"]

	// Flag if > 10 Domain Admins OR > 50 total privileged (PingCastle thresholds)
	isExcessive := domainAdmins > 10 || totalPrivileged > 50

	severity := types.SeverityLow
	count := 0
	if isExcessive {
		severity = types.SeverityMedium
		count = totalPrivileged
	}

	var affectedUsers []types.User
	if isExcessive {
		// Sorted by DN (T_046/B_048): privilegedUsers is a map, so ranging it
		// directly gives a randomized order per process — same input,
		// different JSON, different sha256 across runs.
		dns := make([]string, 0, len(privilegedUsers))
		for dn := range privilegedUsers {
			dns = append(dns, dn)
		}
		sort.Strings(dns)
		for _, dn := range dns {
			for _, user := range data.Users {
				if user.DN == dn {
					affectedUsers = append(affectedUsers, user)
					break
				}
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    severity,
		Category:    string(d.Category()),
		Title:       "Excessive Privileged Accounts",
		Description: "Large number of accounts with administrative privileges increases attack surface. Each privileged account is a potential target for credential theft.",
		Count:       count,
		Details: map[string]interface{}{
			"totalPrivilegedUsers": totalPrivileged,
			"domainAdmins":         domainAdmins,
			"enterpriseAdmins":     enterpriseAdmins,
			"schemaAdmins":         groupCounts["Schema Admins"],
			"administrators":       groupCounts["Administrators"],
			"accountOperators":     groupCounts["Account Operators"],
			"backupOperators":      groupCounts["Backup Operators"],
			"serverOperators":      groupCounts["Server Operators"],
			"printOperators":       groupCounts["Print Operators"],
			"threshold":            "Domain Admins > 10 or total privileged > 50",
			"recommendation":       "Review privileged group memberships and apply least privilege principle.",
		},
	}

	if data.IncludeDetails && len(affectedUsers) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affectedUsers)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewExcessivePrivilegedAccountsDetector())
}
