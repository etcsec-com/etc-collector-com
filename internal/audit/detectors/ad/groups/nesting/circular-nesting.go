package nesting

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CircularNestingDetector checks for circular group membership references
type CircularNestingDetector struct {
	audit.BaseDetector
}

// NewCircularNestingDetector creates a new detector
func NewCircularNestingDetector() *CircularNestingDetector {
	return &CircularNestingDetector{
		BaseDetector: audit.NewBaseDetector("GROUP_CIRCULAR_NESTING", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *CircularNestingDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Build group DN map
	groupDNMap := make(map[string]*types.Group)
	for i := range data.Groups {
		groupDNMap[strings.ToLower(data.Groups[i].DistinguishedName)] = &data.Groups[i]
	}

	var circularGroups []types.Group
	visited := make(map[string]bool)

	var detectCycle func(groupDN string, path map[string]bool) bool
	detectCycle = func(groupDN string, path map[string]bool) bool {
		normalizedDN := strings.ToLower(groupDN)
		if path[normalizedDN] {
			return true // Cycle detected
		}
		if visited[normalizedDN] {
			return false // Already checked, no cycle
		}

		visited[normalizedDN] = true
		path[normalizedDN] = true

		group := groupDNMap[normalizedDN]
		if group != nil {
			for _, parentDN := range group.MemberOf {
				if groupDNMap[strings.ToLower(parentDN)] != nil {
					if detectCycle(parentDN, path) {
						return true
					}
				}
			}
		}

		delete(path, normalizedDN)
		return false
	}

	for _, group := range data.Groups {
		// Clear visited for each new starting point
		visited = make(map[string]bool)
		if detectCycle(group.DistinguishedName, make(map[string]bool)) {
			circularGroups = append(circularGroups, group)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Circular Group Nesting",
		Description: "Groups contain circular membership references. This can cause authentication issues and makes privilege analysis unreliable.",
		Count:       len(circularGroups),
	}

	if len(circularGroups) > 0 {
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedGroupEntities(circularGroups)
		}
		finding.Details = map[string]interface{}{
			"recommendation": "Remove circular nesting by reviewing and restructuring group membership.",
			"impact":         "May cause token bloat, authentication failures, and unreliable access control.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCircularNestingDetector())
}
