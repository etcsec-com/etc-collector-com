package other

import (
	"context"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// RecentObjectsDetector detects AD objects created within the last 10 days
type RecentObjectsDetector struct {
	audit.BaseDetector
}

// NewRecentObjectsDetector creates a new detector
func NewRecentObjectsDetector() *RecentObjectsDetector {
	return &RecentObjectsDetector{
		BaseDetector: audit.NewBaseDetector("RECENT_OBJECTS_CREATED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *RecentObjectsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	tenDaysAgo := data.Now.Add(-10 * 24 * time.Hour)

	newUsers := 0
	for _, user := range data.Users {
		if !user.Created.IsZero() && user.Created.After(tenDaysAgo) {
			newUsers++
		}
	}

	newComputers := 0
	for _, computer := range data.Computers {
		if !computer.Created.IsZero() && computer.Created.After(tenDaysAgo) {
			newComputers++
		}
	}

	newGroups := 0
	for _, group := range data.Groups {
		if !group.Created.IsZero() && group.Created.After(tenDaysAgo) {
			newGroups++
		}
	}

	total := newUsers + newComputers + newGroups

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "AD Objects Created Within the Last 10 Days",
		Description: "New Active Directory objects have been created recently. Review to ensure all new accounts, computers, and groups are authorized and properly configured.",
		Count:       total,
		Details: map[string]interface{}{
			"newUsers":     newUsers,
			"newComputers": newComputers,
			"newGroups":    newGroups,
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewRecentObjectsDetector())
}
