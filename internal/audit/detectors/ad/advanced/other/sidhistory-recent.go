package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SIDHistoryRecentDetector checks for users with SIDHistory that were recently modified
type SIDHistoryRecentDetector struct {
	audit.BaseDetector
}

// NewSIDHistoryRecentDetector creates a new detector
func NewSIDHistoryRecentDetector() *SIDHistoryRecentDetector {
	return &SIDHistoryRecentDetector{
		BaseDetector: audit.NewBaseDetector("SIDHISTORY_RECENT_CHANGES", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *SIDHistoryRecentDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	now := data.Now
	threshold := now.AddDate(0, 0, -90) // 90 days ago

	var affected []types.User
	for _, user := range data.Users {
		if len(user.SIDHistory) == 0 {
			continue
		}

		// Use WhenChanged as a proxy for SIDHistory modification time.
		// If the user object was recently modified and has SIDHistory, flag it.
		if !user.WhenChanged.IsZero() && user.WhenChanged.After(threshold) {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Recent SIDHistory Changes on Objects",
		Description: "Users with SIDHistory attribute that were recently modified. SIDHistory changes can indicate domain migration activity or privilege escalation attempts by injecting SIDs.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSIDHistoryRecentDetector())
}
