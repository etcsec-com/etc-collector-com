package other

import (
	"context"
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

// Detect executes the detection
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

		if helpers.IsInAnyGroup(user.MemberOf, helpers.AdminGroups) {
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
