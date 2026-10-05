package nesting

import (
	"context"
	"sort"
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

	cycleMembers := tarjanCircularGroups(groupDNMap)

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

// tarjanCircularGroups returns, keyed by lowercase DN, every group that
// belongs to a strongly connected component of size >= 2 or that has a
// self-edge (is listed in its own MemberOf), using Tarjan's algorithm on
// the group -> MemberOf graph restricted to known groups.
//
// The single-pass DFS this replaces marked each node visited=true the
// first time it was reached and never cleared that flag on backtrack (only
// the path-stack index was cleared). A node fully explored via one branch
// then blocked every later branch from re-entering it, even when that
// later branch would have closed a different cycle through the same node:
// on a component reachable by more than one path into the same node (e.g.
// X->Y->Z->X plus X->W->Z), whichever branch's DFS exhausted Z first left
// it permanently marked, and the other branch's walk through Z stopped
// short instead of continuing back to close its own cycle - so whether the
// bug triggered, and which node went missing, depended on the order groups
// happened to be enumerated in. Strongly connected components are a
// property of the whole graph rather than of one traversal, so this result
// no longer depends on the order of data.Groups or of any group's
// MemberOf.
func tarjanCircularGroups(groupDNMap map[string]*types.Group) map[string]bool {
	index := make(map[string]int, len(groupDNMap))
	lowlink := make(map[string]int, len(groupDNMap))
	onStack := make(map[string]bool, len(groupDNMap))
	var stack []string
	counter := 0
	circular := make(map[string]bool)

	var strongconnect func(v string)
	strongconnect = func(v string) {
		index[v] = counter
		lowlink[v] = counter
		counter++
		stack = append(stack, v)
		onStack[v] = true

		selfLoop := false
		if group := groupDNMap[v]; group != nil {
			for _, parentDN := range group.MemberOf {
				w := strings.ToLower(parentDN)
				if groupDNMap[w] == nil {
					continue
				}
				if w == v {
					selfLoop = true
				}
				if _, seen := index[w]; !seen {
					strongconnect(w)
					if lowlink[w] < lowlink[v] {
						lowlink[v] = lowlink[w]
					}
				} else if onStack[w] {
					if index[w] < lowlink[v] {
						lowlink[v] = index[w]
					}
				}
			}
		}

		if lowlink[v] == index[v] {
			var component []string
			for {
				n := len(stack) - 1
				w := stack[n]
				stack = stack[:n]
				onStack[w] = false
				component = append(component, w)
				if w == v {
					break
				}
			}
			if len(component) >= 2 || selfLoop {
				for _, n := range component {
					circular[n] = true
				}
			}
		}
	}

	// Root selection order does not change which SCCs exist, only the order
	// they are discovered in - but Go's map iteration order is randomized on
	// purpose, so leaving it unsorted makes any test that depends on one SCC
	// finishing before the DFS reaches another node flaky (green or red
	// depending on the run). Sorting makes the traversal, and therefore any
	// test asserting on it, reproducible.
	roots := make([]string, 0, len(groupDNMap))
	for dn := range groupDNMap {
		roots = append(roots, dn)
	}
	sort.Strings(roots)

	for _, dn := range roots {
		if _, seen := index[dn]; !seen {
			strongconnect(dn)
		}
	}

	return circular
}

func init() {
	audit.MustRegister(NewCircularNestingDetector())
}
