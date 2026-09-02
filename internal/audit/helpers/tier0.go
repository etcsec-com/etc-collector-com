package helpers

import (
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DefaultTier0AdminGroupNames is the canonical list of Tier 0 admin group
// sAMAccountNames recognized out-of-the-box. Names are matched case-
// insensitively. This list is the one ANSSI PA-099 R23 implicitly defines
// (Tier 0 admin and security groups).
//
// Customers with custom Tier 0 admin groups should pass their group DNs
// to Tier0Members / Tier0Groups via the customGroupDNs argument.
var DefaultTier0AdminGroupNames = []string{
	"domain admins",
	"enterprise admins",
	"schema admins",
	"administrators",
	"account operators",
	"backup operators",
	"server operators",
	"print operators",
	"protected users",
	"key admins",
	"enterprise key admins",
	"dnsadmins",
}

// maxRecursionDepth caps the recursive group expansion to prevent infinite
// loops on cyclic memberships and pathological forests.
const maxRecursionDepth = 10

// Tier0Members returns the lowercase DN set of all USERS considered Tier 0,
// computed as the union of three sources:
//
//  1. Direct + transitive members of the well-known Tier 0 admin groups
//     (see DefaultTier0AdminGroupNames) plus any custom group DNs supplied.
//  2. Users whose AdminCount=1 (i.e. AdminSDHolder-protected at last cycle).
//  3. Members of any nested group reached via recursive expansion.
//
// The recursion is bounded at maxRecursionDepth and uses an explicit visited
// set to avoid cycles.
//
// v3.1.18 — replaces the v3.1.17 approach which only matched the 12 hardcoded
// group names against direct members (no recursion, no AdminCount, no custom
// config). That older approach missed Tier 0 accounts hidden behind nested
// groups or custom org structures.
func Tier0Members(data *audit.DetectorData, customGroupDNs []string) map[string]bool {
	out := map[string]bool{}
	if data == nil {
		return out
	}

	// Step 1+3: walk the Tier 0 group set and recurse.
	tier0Groups := Tier0Groups(data, customGroupDNs)
	visited := map[string]bool{}
	for groupDN := range tier0Groups {
		expandGroupMembers(data, groupDN, out, visited, 0)
	}

	// Step 2: add every user whose AdminCount=1.
	for _, u := range data.Users {
		if u.AdminCount {
			out[strings.ToLower(u.DN)] = true
		}
	}

	return out
}

// Tier0Groups returns the lowercase DN set of all GROUPS considered Tier 0
// — the seed set used by Tier0Members for recursive member expansion.
//
// Sources:
//  1. Groups whose sAMAccountName matches DefaultTier0AdminGroupNames.
//  2. Groups whose DN is explicitly listed in customGroupDNs (case-insensitive).
//  3. Groups discovered transitively as nested members of (1) or (2).
//
// Use this when a detector needs to evaluate a control SCOPED to Tier 0
// containers (e.g. R23 — permissions on Tier 0 accounts and groups in AD).
func Tier0Groups(data *audit.DetectorData, customGroupDNs []string) map[string]bool {
	out := map[string]bool{}
	if data == nil {
		return out
	}

	// Index groups by DN for transitive expansion.
	byDN := map[string]types.Group{}
	for _, g := range data.Groups {
		byDN[strings.ToLower(g.DN)] = g
	}

	// Seed: well-known Tier 0 sAMAccountName matches.
	for _, g := range data.Groups {
		if isDefaultTier0Name(g.SAMAccountName) {
			out[strings.ToLower(g.DN)] = true
		}
	}
	// Seed: customer-supplied custom DNs (validated against actually-collected groups).
	for _, dn := range customGroupDNs {
		k := strings.ToLower(strings.TrimSpace(dn))
		if k == "" {
			continue
		}
		if _, ok := byDN[k]; ok {
			out[k] = true
		}
		// Silently skip DNs not present in data.Groups — they may simply
		// not exist anymore. Detectors using this helper log no-op.
	}

	// Transitive: any group nested inside a Tier 0 group is itself Tier 0.
	visited := map[string]bool{}
	queue := make([]string, 0, len(out))
	for k := range out {
		queue = append(queue, k)
	}
	for len(queue) > 0 {
		dn := queue[0]
		queue = queue[1:]
		if visited[dn] {
			continue
		}
		visited[dn] = true

		g, ok := byDN[dn]
		if !ok {
			continue
		}
		for _, memberDN := range g.Members {
			mk := strings.ToLower(memberDN)
			if _, isGroup := byDN[mk]; isGroup && !out[mk] {
				out[mk] = true
				queue = append(queue, mk)
			}
		}
	}

	return out
}

// isDefaultTier0Name returns true when a group sAMAccountName matches one of
// the canonical Tier 0 admin group names (case-insensitive comparison).
func isDefaultTier0Name(sam string) bool {
	s := strings.ToLower(strings.TrimSpace(sam))
	for _, n := range DefaultTier0AdminGroupNames {
		if s == n {
			return true
		}
	}
	return false
}

// expandGroupMembers walks a group's direct members and recursively expands
// any nested group encountered. USER members are added to `out`; GROUP
// members trigger recursion. Bounded by maxRecursionDepth and `visited`.
func expandGroupMembers(data *audit.DetectorData, groupDN string, out, visited map[string]bool, depth int) {
	if depth > maxRecursionDepth {
		return
	}
	gk := strings.ToLower(groupDN)
	if visited[gk] {
		return
	}
	visited[gk] = true

	// Find the group object.
	var g *types.Group
	for i := range data.Groups {
		if strings.EqualFold(data.Groups[i].DN, groupDN) {
			g = &data.Groups[i]
			break
		}
	}
	if g == nil {
		return
	}

	// Build a quick "is this DN a known group?" lookup.
	groupSet := map[string]bool{}
	for _, gg := range data.Groups {
		groupSet[strings.ToLower(gg.DN)] = true
	}

	for _, memberDN := range g.Members {
		mk := strings.ToLower(memberDN)
		if groupSet[mk] {
			expandGroupMembers(data, memberDN, out, visited, depth+1)
		} else {
			// Treat as user/computer DN. Compliance Tier 0 detectors care
			// about user identities; computer accounts in admin groups are
			// uncommon and addressed elsewhere (DCSync detector).
			out[mk] = true
		}
	}
}
