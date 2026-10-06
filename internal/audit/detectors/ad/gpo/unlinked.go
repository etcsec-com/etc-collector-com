package gpo

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// UnlinkedDetector checks for unlinked GPOs
type UnlinkedDetector struct {
	audit.BaseDetector
}

// NewUnlinkedDetector creates a new detector
func NewUnlinkedDetector() *UnlinkedDetector {
	return &UnlinkedDetector{
		BaseDetector: audit.NewBaseDetector("GPO_UNLINKED", audit.CategoryGPO),
	}
}

// Default GPO GUIDs to exclude
var excludeGuids = []string{
	"31B2F340-016D-11D2-945F-00C04FB984F9", // Default Domain Policy
	"6AC1786C-016F-11D2-945F-00C04FB984F9", // Default Domain Controllers Policy
}

// Detect executes the detection
func (d *UnlinkedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Get linked GPO GUIDs
	linkedGuids := make(map[string]bool)
	for _, link := range data.GPOLinks {
		linkedGuids[strings.ToLower(link.GPOCN)] = true
	}

	var affected []types.GPO
	for _, gpo := range data.GPOs {
		// Check if linked
		if linkedGuids[strings.ToLower(gpo.CN)] {
			continue
		}

		// Exclude default GPOs
		isExcluded := false
		for _, guid := range excludeGuids {
			if strings.Contains(strings.ToUpper(gpo.CN), guid) {
				isExcluded = true
				break
			}
		}
		if isExcluded {
			continue
		}

		affected = append(affected, gpo)
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Unlinked Group Policy Objects",
		Description: "GPOs exist that are not linked to any OU, domain, or site. These may be orphaned or indicate incomplete deployment.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGPOEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUnlinkedDetector())
}
