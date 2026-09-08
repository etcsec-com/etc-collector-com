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

// groupDN returns the DN a provider actually populates (parser.go writes DN,
// never DistinguishedName), falling back to the alias for a DetectorData
// rehydrated from an imported audit JSON. Same pattern already used by
// engine.go's PrivilegedGroupMemberChanges collection.
func groupDN(g types.Group) string {
	if g.DN != "" {
		return g.DN
	}
	return g.DistinguishedName
}

// Detect executes the detection
func (d *CircularNestingDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Build group DN map
	groupDNMap := make(map[string]*types.Group, len(data.Groups))
	for i := range data.Groups {
		dn := groupDN(data.Groups[i])
		if dn == "" {
			continue
		}
		groupDNMap[strings.ToLower(dn)] = &data.Groups[i]
	}

	// Single DFS pass recording exactly the nodes that participate in a
	// cycle: the previous algorithm flagged every node from which a cycle is
	// REACHABLE, not just the nodes IN the cycle - on A -> B -> C -> B, A was
	// reported alongside the real cycle {B, C}.
	// `path` is the current DFS stack in order; `pathIndex` gives each DN's
	// position on it. When a neighbour is found already on the stack, every
	// node from that position to the top is part of the cycle.
	cycleMembers := make(map[string]bool)
	visited := make(map[string]bool, len(data.Groups))
	var path []string
	pathIndex := make(map[string]int)

	var visit func(dn string)
	visit = func(dn string) {
		if idx, onPath := pathIndex[dn]; onPath {
			for _, n := range path[idx:] {
				cycleMembers[n] = true
			}
			return
		}
		if visited[dn] {
			return
		}
		visited[dn] = true

		pathIndex[dn] = len(path)
		path = append(path, dn)

		if group := groupDNMap[dn]; group != nil {
			for _, parentDN := range group.MemberOf {
				parentNorm := strings.ToLower(parentDN)
				if groupDNMap[parentNorm] != nil {
					visit(parentNorm)
				}
			}
		}

		path = path[:len(path)-1]
		delete(pathIndex, dn)
	}

	for i := range data.Groups {
		dn := groupDN(data.Groups[i])
		if dn == "" {
			continue
		}
		normalized := strings.ToLower(dn)
		if !visited[normalized] {
			visit(normalized)
		}
	}

	var circularGroups []types.Group
	for i := range data.Groups {
		dn := groupDN(data.Groups[i])
		if dn != "" && cycleMembers[strings.ToLower(dn)] {
			circularGroups = append(circularGroups, data.Groups[i])
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
			// memberOf (Microsoft Learn, Active Directory schema - Member-Of;
			// MS-ADTS 3.1.1.1.4 "Linked Attributes") is a back-link computed
			// per domain and not replicated cross-domain: a cycle that closes
			// through a universal group in another domain of the same forest
			// stays invisible while the audit only collects this one domain.
			"limitation": "A cycle passing through a group in a different domain is not detected unless that domain is also audited (memberOf is a per-domain back-link).",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCircularNestingDetector())
}
