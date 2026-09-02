package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DcTimeSyncDetector checks for DC time synchronization issues
type DcTimeSyncDetector struct {
	audit.BaseDetector
}

// NewDcTimeSyncDetector creates a new detector
func NewDcTimeSyncDetector() *DcTimeSyncDetector {
	return &DcTimeSyncDetector{
		BaseDetector: audit.NewBaseDetector("DC_TIME_SYNC_ISSUE", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *DcTimeSyncDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	sevenDaysAgo := data.Now.AddDate(0, 0, -7)

	var possibleTimeSyncIssues []string
	for _, dc := range data.DomainControllers {
		if !dc.LastLogon.IsZero() && dc.LastLogon.Before(sevenDaysAgo) {
			possibleTimeSyncIssues = append(possibleTimeSyncIssues, dc.SAMAccountName)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "DC Time Synchronization Review",
		Description: "Domain controllers with potential time sync issues detected. Kerberos requires time difference < 5 minutes.",
		Count:       len(possibleTimeSyncIssues),
		Details: map[string]interface{}{
			"possibleIssues": possibleTimeSyncIssues,
			"recommendation": "Run 'w32tm /query /status' on each DC to verify time configuration.",
		},
	}

	if len(possibleTimeSyncIssues) > 0 {
		finding.AffectedEntities = toAffectedComputerNameEntitiesTimeSync(possibleTimeSyncIssues)
	}

	return []types.Finding{finding}
}

// toAffectedComputerNameEntitiesTimeSync converts a list of computer names to affected entities
func toAffectedComputerNameEntitiesTimeSync(names []string) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(names))
	for i, name := range names {
		entities[i] = types.AffectedEntity{
			Type:           "computer",
			SAMAccountName: name,
		}
	}
	return entities
}

func init() {
	audit.MustRegister(NewDcTimeSyncDetector())
}
