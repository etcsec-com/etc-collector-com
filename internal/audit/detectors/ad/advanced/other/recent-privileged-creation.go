package other

import (
	"context"
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// RecentPrivilegedCreationDetector detects recently created privileged accounts
type RecentPrivilegedCreationDetector struct {
	audit.BaseDetector
}

// NewRecentPrivilegedCreationDetector creates a new detector
func NewRecentPrivilegedCreationDetector() *RecentPrivilegedCreationDetector {
	return &RecentPrivilegedCreationDetector{
		BaseDetector: audit.NewBaseDetector("RECENT_PRIVILEGED_CREATION", audit.CategoryAdvanced),
	}
}

// isDirectMemberOfGroup reports whether memberOf contains an exact "CN=<group>,"
// component (case-insensitive), not merely a substring match. helpers.IsInAnyGroup
// matches "cn=<groupe>" as a raw substring of the DN, so a group literally named
// "Domain AdminsX" (or any group whose CN starts with "Domain Admins") would also
// match "Domain Admins" - a false positive this detector cannot afford at Critical
// review weight. Requiring the DN component to end at a comma (or the DN's end)
// pins the match to the exact CN.
func isDirectMemberOfGroup(memberOf []string, group string) bool {
	needle := "cn=" + strings.ToLower(group)
	for _, dn := range memberOf {
		dnLower := strings.ToLower(dn)
		idx := strings.Index(dnLower, needle)
		if idx != 0 {
			continue // must be the first RDN of the DN
		}
		rest := dnLower[len(needle):]
		if rest == "" || rest[0] == ',' {
			return true
		}
	}
	return false
}

// Detect executes the detection.
//
// This is a product heuristic, not a requirement drawn from any vendor or
// regulatory referential: no ANSSI/CIS/Microsoft source prescribes a
// "privileged account created in the last 10 days" rule, hence the Info
// severity and the plain (non-normative) description below. Group
// membership is matched on the exact CN component (isDirectMemberOfGroup),
// not helpers.IsInAnyGroup's substring match, to avoid a group like "Domain
// AdminsX" being counted as "Domain Admins". This still only sees direct
// memberOf entries: it does not resolve nested group membership or
// primaryGroupID, so a privileged account added via a nested group or via
// its primary group is not caught.
func (d *RecentPrivilegedCreationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	tenDaysAgo := data.Now.Add(-10 * 24 * time.Hour)

	var affected []types.User

	for _, user := range data.Users {
		if user.Created.IsZero() {
			continue
		}

		if !user.Created.After(tenDaysAgo) {
			continue
		}

		for _, group := range helpers.AdminGroups {
			if isDirectMemberOfGroup(user.MemberOf, group) {
				affected = append(affected, user)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Recent Privileged Account Creation Activity",
		Description: "New privileged accounts have been created in the last 10 days. Unauthorized creation of administrative accounts may indicate compromise or insider threats.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewRecentPrivilegedCreationDetector())
}
