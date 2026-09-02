package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DsHeuristicsModifiedDetector detects modified dsHeuristics attribute
type DsHeuristicsModifiedDetector struct {
	audit.BaseDetector
}

// NewDsHeuristicsModifiedDetector creates a new detector
func NewDsHeuristicsModifiedDetector() *DsHeuristicsModifiedDetector {
	return &DsHeuristicsModifiedDetector{
		BaseDetector: audit.NewBaseDetector("DS_HEURISTICS_MODIFIED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *DsHeuristicsModifiedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		return []types.Finding{{
			Type:        d.ID(),
			Severity:    types.SeverityMedium,
			Category:    string(d.Category()),
			Title:       "dsHeuristics Status Unknown",
			Description: "Unable to check dsHeuristics attribute.",
			Count:       0,
		}}
	}

	dsHeuristics := data.DomainInfo.DsHeuristics
	isModified := dsHeuristics != ""

	// Check for specific dangerous settings
	var dangerousSettings []string
	if len(dsHeuristics) >= 7 && dsHeuristics[6] == '2' {
		dangerousSettings = append(dangerousSettings, "Anonymous LDAP operations allowed (position 7)")
	}
	if len(dsHeuristics) >= 3 && dsHeuristics[2] == '1' {
		dangerousSettings = append(dangerousSettings, "List Object mode disabled (position 3)")
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "dsHeuristics Modified",
		Description: "The dsHeuristics attribute has been modified from defaults. This may weaken AD security or enable dangerous features.",
		Count:       0,
	}

	if isModified {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"currentValue":   dsHeuristics,
			"recommendation": "Review dsHeuristics value and document any intentional modifications.",
		}
		if len(dangerousSettings) > 0 {
			finding.Details["dangerousSettings"] = dangerousSettings
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDsHeuristicsModifiedDetector())
}
