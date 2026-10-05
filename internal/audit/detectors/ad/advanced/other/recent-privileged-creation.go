package other

import (
	"context"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/privgroups"
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

// recentPrivilegedCreationSIDSuffixes is helpers.AdminGroups (Domain
// Admins, Enterprise Admins, Schema Admins, Administrators, Account
// Operators, Server Operators, Backup Operators, Print Operators)
// translated to RID suffixes: matched by SID, not CN, so a group
// like "Domain AdminsX" (a past false-positive risk of a plain CN
// substring match) or any other homonym cannot false-positive, and a
// renamed real group is still caught. All 8 suffixes already appear in
// types.PrivilegedSIDSuffixes.
var recentPrivilegedCreationSIDSuffixes = []string{"-512", "-519", "-518", "-544", "-548", "-549", "-551", "-550"}

// Detect executes the detection.
//
// This is a product heuristic, not a requirement drawn from any vendor or
// regulatory referential: no ANSSI/CIS/Microsoft source prescribes a
// "privileged account created in the last 10 days" rule, hence the Info
// severity and the plain (non-normative) description below. Group
// membership is matched by SID suffix (privgroups.DNsBySIDSuffix), not by
// CN, so a homonym group like "Domain AdminsX" cannot be counted as
// "Domain Admins" and a renamed real group (non-English forest) is not
// missed. This still only sees direct memberOf entries: it does not
// resolve nested group membership or primaryGroupID, so a privileged
// account added via a nested group or via its primary group is not caught.
func (d *RecentPrivilegedCreationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	tenDaysAgo := data.Now.Add(-10 * 24 * time.Hour)

	var affected []types.User

	adminDNs := privgroups.DNsBySIDSuffix(data, recentPrivilegedCreationSIDSuffixes)

	for _, user := range data.Users {
		if user.Created.IsZero() {
			continue
		}

		if !user.Created.After(tenDaysAgo) {
			continue
		}

		if privgroups.IsMemberOfAny(user.MemberOf, adminDNs) {
			affected = append(affected, user)
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
