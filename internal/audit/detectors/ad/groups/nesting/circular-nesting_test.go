package nesting

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	cnDomainDN    = "DC=example,DC=com"
	cnGroupA      = "CN=GroupA,OU=Groups," + cnDomainDN
	cnGroupB      = "CN=GroupB,OU=Groups," + cnDomainDN
	cnGroupC      = "CN=GroupC,OU=Groups," + cnDomainDN
	cnGroupD      = "CN=GroupD,OU=Groups," + cnDomainDN
	cnGroupE      = "CN=GroupE,OU=Groups," + cnDomainDN
	cnGroupBranch = "CN=GroupBranch,OU=Groups," + cnDomainDN
	cnGroupGhost  = "CN=GroupGhost,OU=Groups," + cnDomainDN
	cnGroupSccX   = "CN=GroupSccX,OU=Groups," + cnDomainDN
	cnGroupSccY   = "CN=GroupSccY,OU=Groups," + cnDomainDN
	cnGroupSccZ   = "CN=GroupSccZ,OU=Groups," + cnDomainDN
	cnGroupSccW   = "CN=GroupSccW,OU=Groups," + cnDomainDN
	cnGroupSccP   = "CN=GroupSccP,OU=Groups," + cnDomainDN
	cnGroupSccQ   = "CN=GroupSccQ,OU=Groups," + cnDomainDN
	cnGroupSccR   = "CN=GroupSccR,OU=Groups," + cnDomainDN
	cnGroupLeadIn  = "CN=GroupLeadIn,OU=Groups," + cnDomainDN
	cnGroupACycle1 = "CN=a-cycle-1,OU=Groups," + cnDomainDN
	cnGroupACycle2 = "CN=a-cycle-2,OU=Groups," + cnDomainDN
	cnGroupPCycle1 = "CN=p-cycle-1,OU=Groups," + cnDomainDN
	cnGroupPCycle2 = "CN=p-cycle-2,OU=Groups," + cnDomainDN
)

func cnDetect(t *testing.T, groups []types.Group) types.Finding {
	t.Helper()
	data := &audit.DetectorData{IncludeDetails: true, Groups: groups}
	findings := NewCircularNestingDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// TestCircularNesting_FiresOnRealCycle is the RED->GREEN case: the
// detector indexed and walked groups by Group.DistinguishedName, an alias
// field parser.go never assigns (only DN is populated), so every key
// collapsed to "" and a real A<->B cycle went undetected.
func TestCircularNesting_FiresOnRealCycle(t *testing.T) {
	f := cnDetect(t, []types.Group{
		{DN: cnGroupA, SAMAccountName: "GroupA", MemberOf: []string{cnGroupB}},
		{DN: cnGroupB, SAMAccountName: "GroupB", MemberOf: []string{cnGroupA}},
	})
	if f.Count != 2 {
		t.Fatalf("both groups in an A<->B cycle must fire, got count=%d", f.Count)
	}
}

// TestCircularNesting_NoCycleDoesNotFire guards against the DN-collision
// false positive: before the fix, every group's key was "" so a SECOND group
// sharing that empty key could look like it referenced itself.
func TestCircularNesting_NoCycleDoesNotFire(t *testing.T) {
	f := cnDetect(t, []types.Group{
		{DN: cnGroupA, SAMAccountName: "GroupA", MemberOf: nil},
		{DN: cnGroupB, SAMAccountName: "GroupB", MemberOf: []string{cnGroupA}},
	})
	if f.Count != 0 {
		t.Fatalf("a plain nesting chain with no cycle must not fire, got count=%d", f.Count)
	}
}

// TestCircularNesting_OnlyCycleMembersReported covers a second defect:
// on A -> B -> C -> B, the old algorithm flagged A too (a cycle is
// REACHABLE from A) even though A does not participate in the cycle. Only
// {B, C} may fire.
func TestCircularNesting_OnlyCycleMembersReported(t *testing.T) {
	f := cnDetect(t, []types.Group{
		{DN: cnGroupA, SAMAccountName: "GroupA", MemberOf: []string{cnGroupB}},
		{DN: cnGroupB, SAMAccountName: "GroupB", MemberOf: []string{cnGroupC}},
		{DN: cnGroupC, SAMAccountName: "GroupC", MemberOf: []string{cnGroupB}},
	})
	if f.Count != 2 {
		t.Fatalf("only the 2 groups actually in the B<->C cycle must fire, got count=%d", f.Count)
	}
	names := map[string]bool{}
	for _, e := range f.AffectedEntities {
		names[e.Name] = true
	}
	if names["GroupA"] {
		t.Fatal("GroupA merely reaches the cycle, it is not part of it, and must not be reported")
	}
	if !names["GroupB"] || !names["GroupC"] {
		t.Fatalf("GroupB and GroupC are the real cycle and must both be reported, got %v", names)
	}
}

// TestCircularNesting_DistinguishedNameAliasFallback covers the JSON-rehydrate
// path: a DetectorData restored from an exported audit may only carry the
// legacy DistinguishedName alias field.
func TestCircularNesting_DistinguishedNameAliasFallback(t *testing.T) {
	f := cnDetect(t, []types.Group{
		{DistinguishedName: cnGroupA, SAMAccountName: "GroupA", MemberOf: []string{cnGroupB}},
		{DistinguishedName: cnGroupB, SAMAccountName: "GroupB", MemberOf: []string{cnGroupA}},
	})
	if f.Count != 2 {
		t.Fatalf("the DistinguishedName alias must still resolve a real cycle, got count=%d", f.Count)
	}
}

// TestCircularNesting_SelfLoop covers a group that lists itself in its own
// MemberOf: the DFS must close the cycle on the very first recursive call
// and report the single node. Also asserts Type and Severity, which no
// other test in this file checks explicitly.
func TestCircularNesting_SelfLoop(t *testing.T) {
	f := cnDetect(t, []types.Group{
		{DN: cnGroupA, SAMAccountName: "GroupA", MemberOf: []string{cnGroupA}},
	})
	if f.Count != 1 {
		t.Fatalf("a group that is a member of itself must fire once, got count=%d", f.Count)
	}
	if f.Type != "GROUP_CIRCULAR_NESTING" {
		t.Fatalf("unexpected Type: %q", f.Type)
	}
	if f.Severity != types.SeverityMedium {
		t.Fatalf("unexpected Severity: %q", f.Severity)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].Name != "GroupA" {
		t.Fatalf("expected GroupA alone, got %v", f.AffectedEntities)
	}
}

// TestCircularNesting_ThreeNodeCycle covers a cycle spanning three groups
// (A -> B -> C -> A): all three must fire, not just the pair closest to
// where the cycle is detected.
func TestCircularNesting_ThreeNodeCycle(t *testing.T) {
	f := cnDetect(t, []types.Group{
		{DN: cnGroupA, SAMAccountName: "GroupA", MemberOf: []string{cnGroupB}},
		{DN: cnGroupB, SAMAccountName: "GroupB", MemberOf: []string{cnGroupC}},
		{DN: cnGroupC, SAMAccountName: "GroupC", MemberOf: []string{cnGroupA}},
	})
	if f.Count != 3 {
		t.Fatalf("a 3-node cycle A->B->C->A must report all 3 members, got count=%d", f.Count)
	}
	names := map[string]bool{}
	for _, e := range f.AffectedEntities {
		names[e.Name] = true
	}
	if !names["GroupA"] || !names["GroupB"] || !names["GroupC"] {
		t.Fatalf("expected GroupA, GroupB and GroupC, got %v", names)
	}
}

// TestCircularNesting_TwoDisjointCycles covers two independent cycles
// (A<->B and D<->E) processed as separate DFS trees from the top-level
// loop: neither must contaminate the other's membership.
func TestCircularNesting_TwoDisjointCycles(t *testing.T) {
	f := cnDetect(t, []types.Group{
		{DN: cnGroupA, SAMAccountName: "GroupA", MemberOf: []string{cnGroupB}},
		{DN: cnGroupB, SAMAccountName: "GroupB", MemberOf: []string{cnGroupA}},
		{DN: cnGroupD, SAMAccountName: "GroupD", MemberOf: []string{cnGroupE}},
		{DN: cnGroupE, SAMAccountName: "GroupE", MemberOf: []string{cnGroupD}},
	})
	if f.Count != 4 {
		t.Fatalf("two disjoint 2-node cycles must report all 4 members, got count=%d", f.Count)
	}
	names := map[string]bool{}
	for _, e := range f.AffectedEntities {
		names[e.Name] = true
	}
	for _, want := range []string{"GroupA", "GroupB", "GroupD", "GroupE"} {
		if !names[want] {
			t.Fatalf("expected %s among affected entities, got %v", want, names)
		}
	}
}

// TestCircularNesting_CaseInsensitiveDN covers a cycle whose two halves
// reference each other with differently-cased DN strings (AD itself is
// case-insensitive for DN comparison): the ToLower normalization must make
// the map lookup and the pathIndex match regardless of case.
func TestCircularNesting_CaseInsensitiveDN(t *testing.T) {
	f := cnDetect(t, []types.Group{
		{DN: "CN=GroupX,OU=Groups,DC=example,DC=com", SAMAccountName: "GroupX", MemberOf: []string{"CN=GROUPY,OU=GROUPS,DC=EXAMPLE,DC=COM"}},
		{DN: "cn=groupy,ou=groups,dc=example,dc=com", SAMAccountName: "GroupY", MemberOf: []string{"CN=GroupX,OU=Groups,DC=example,DC=com"}},
	})
	if f.Count != 2 {
		t.Fatalf("a cycle referenced with mismatched DN case must still fire, got count=%d", f.Count)
	}
}

// TestCircularNesting_UnknownParentIgnored covers a MemberOf entry that
// points at a DN absent from the collected groups (e.g. a group outside the
// audited domain, or one the collector could not resolve): it must be
// silently skipped, never treated as a cycle.
func TestCircularNesting_UnknownParentIgnored(t *testing.T) {
	f := cnDetect(t, []types.Group{
		{DN: cnGroupA, SAMAccountName: "GroupA", MemberOf: []string{cnGroupGhost}},
	})
	if f.Count != 0 {
		t.Fatalf("memberOf pointing at an unknown group must not fire, got count=%d", f.Count)
	}
}

// TestCircularNesting_EmptyDNGroupsIgnored covers groups with neither DN nor
// DistinguishedName populated (a malformed collection record): they must be
// skipped entirely rather than colliding on the empty-string map key.
func TestCircularNesting_EmptyDNGroupsIgnored(t *testing.T) {
	f := cnDetect(t, []types.Group{
		{SAMAccountName: "Ghost1", MemberOf: []string{""}},
		{SAMAccountName: "Ghost2", MemberOf: []string{""}},
	})
	if f.Count != 0 {
		t.Fatalf("groups with an empty DN must not fire, got count=%d", f.Count)
	}
}

// TestCircularNesting_SiblingBranchExcludedFromCycle covers a group with TWO
// memberOf parents, where the first (processed and fully backtracked before
// the second) does not lead to any cycle: the completed-and-abandoned first
// branch must not leak into the cycle discovered through the second parent.
// This is the scenario that distinguishes a DFS that truncates `path` on
// backtrack from one that only deletes the pathIndex entry.
func TestCircularNesting_SiblingBranchExcludedFromCycle(t *testing.T) {
	f := cnDetect(t, []types.Group{
		{DN: cnGroupA, SAMAccountName: "GroupA", MemberOf: []string{cnGroupBranch, cnGroupD}},
		{DN: cnGroupBranch, SAMAccountName: "GroupBranch", MemberOf: nil},
		{DN: cnGroupD, SAMAccountName: "GroupD", MemberOf: []string{cnGroupA}},
	})
	if f.Count != 2 {
		t.Fatalf("only GroupA and GroupD form the cycle, GroupBranch must be excluded, got count=%d", f.Count)
	}
	names := map[string]bool{}
	for _, e := range f.AffectedEntities {
		names[e.Name] = true
	}
	if names["GroupBranch"] {
		t.Fatal("GroupBranch is a dead-end sibling, never part of any cycle, and must not be reported")
	}
	if !names["GroupA"] || !names["GroupD"] {
		t.Fatalf("expected GroupA and GroupD, got %v", names)
	}
}

// permutations4 returns all 24 orderings of [0,1,2,3] (standard recursive
// swap-based generation; the visiting order of the outer loop does not
// matter, only that all 24 distinct orderings are produced).
func permutations4() [][4]int {
	base := [4]int{0, 1, 2, 3}
	var result [][4]int
	var permute func(arr [4]int, k int)
	permute = func(arr [4]int, k int) {
		if k == len(arr) {
			var cp [4]int
			copy(cp[:], arr[:])
			result = append(result, cp)
			return
		}
		for i := k; i < len(arr); i++ {
			arr[k], arr[i] = arr[i], arr[k]
			permute(arr, k+1)
			arr[k], arr[i] = arr[i], arr[k]
		}
	}
	permute(base, 0)
	return result
}

// TestCircularNesting_TwoEntryComponentAllOrders reproduces the DC01
// under-count: a strongly connected component reachable by two distinct
// paths into the same node (X->Y->Z->X plus X->W->Z, sharing Z as the
// re-entry point and X as the common source) must be reported in its
// entirety - all 4 groups - independent of the order the groups are
// enumerated in. Exercised across all 24 permutations of the 4-group input.
func TestCircularNesting_TwoEntryComponentAllOrders(t *testing.T) {
	base := []types.Group{
		{DN: cnGroupSccX, SAMAccountName: "GroupX", MemberOf: []string{cnGroupSccY, cnGroupSccW}},
		{DN: cnGroupSccY, SAMAccountName: "GroupY", MemberOf: []string{cnGroupSccZ}},
		{DN: cnGroupSccZ, SAMAccountName: "GroupZ", MemberOf: []string{cnGroupSccX}},
		{DN: cnGroupSccW, SAMAccountName: "GroupW", MemberOf: []string{cnGroupSccZ}},
	}
	for _, perm := range permutations4() {
		ordered := []types.Group{base[perm[0]], base[perm[1]], base[perm[2]], base[perm[3]]}
		f := cnDetect(t, ordered)
		if f.Count != 4 {
			t.Fatalf("order %v: expected all 4 groups in the X/Y/Z/W component, got count=%d", perm, f.Count)
		}
		names := map[string]bool{}
		for _, e := range f.AffectedEntities {
			names[e.Name] = true
		}
		for _, want := range []string{"GroupX", "GroupY", "GroupZ", "GroupW"} {
			if !names[want] {
				t.Fatalf("order %v: expected %s among affected entities, got %v", perm, want, names)
			}
		}
	}
}

// TestCircularNesting_TwoCyclesShareNode covers two 2-node cycles (P<->Q
// and Q<->R) that share GroupQ: because Q can reach both P and R, and both
// P and R can reach back to Q, all three are mutually reachable and must
// merge into a single 3-member component rather than being treated as two
// separate 2-member cycles.
func TestCircularNesting_TwoCyclesShareNode(t *testing.T) {
	f := cnDetect(t, []types.Group{
		{DN: cnGroupSccP, SAMAccountName: "GroupP", MemberOf: []string{cnGroupSccQ}},
		{DN: cnGroupSccQ, SAMAccountName: "GroupQ", MemberOf: []string{cnGroupSccP, cnGroupSccR}},
		{DN: cnGroupSccR, SAMAccountName: "GroupR", MemberOf: []string{cnGroupSccQ}},
	})
	if f.Count != 3 {
		t.Fatalf("two cycles sharing GroupQ must merge into one 3-member component, got count=%d", f.Count)
	}
	names := map[string]bool{}
	for _, e := range f.AffectedEntities {
		names[e.Name] = true
	}
	for _, want := range []string{"GroupP", "GroupQ", "GroupR"} {
		if !names[want] {
			t.Fatalf("expected %s among affected entities, got %v", want, names)
		}
	}
}

// TestCircularNesting_NodeLeadingToComponentExcluded covers a node whose
// only edge leads INTO the X/Y/Z/W component (GroupLeadIn -> GroupX) with
// no edge back: GroupLeadIn merely reaches the component, it does not
// belong to it, and must stay excluded even though the component itself
// (unlike a single group->group cycle) has more than one entry point.
func TestCircularNesting_NodeLeadingToComponentExcluded(t *testing.T) {
	f := cnDetect(t, []types.Group{
		{DN: cnGroupLeadIn, SAMAccountName: "GroupLeadIn", MemberOf: []string{cnGroupSccX}},
		{DN: cnGroupSccX, SAMAccountName: "GroupX", MemberOf: []string{cnGroupSccY, cnGroupSccW}},
		{DN: cnGroupSccY, SAMAccountName: "GroupY", MemberOf: []string{cnGroupSccZ}},
		{DN: cnGroupSccZ, SAMAccountName: "GroupZ", MemberOf: []string{cnGroupSccX}},
		{DN: cnGroupSccW, SAMAccountName: "GroupW", MemberOf: []string{cnGroupSccZ}},
	})
	if f.Count != 4 {
		t.Fatalf("GroupLeadIn only reaches the component, expected the 4 real members (X,Y,Z,W), got count=%d", f.Count)
	}
	names := map[string]bool{}
	for _, e := range f.AffectedEntities {
		names[e.Name] = true
	}
	if names["GroupLeadIn"] {
		t.Fatal("GroupLeadIn merely reaches the component, it is not part of it, and must not be reported")
	}
	for _, want := range []string{"GroupX", "GroupY", "GroupZ", "GroupW"} {
		if !names[want] {
			t.Fatalf("expected %s among affected entities, got %v", want, names)
		}
	}
}

// TestCircularNesting_ComponentFinishedBeforeSharedEdgeAllOrders reproduces
// the review counter-example: a-cycle-1 <-> a-cycle-2 form one component,
// p-cycle-1 <-> p-cycle-2 form a second, disjoint component, and p-cycle-1
// is ALSO a member of a-cycle-1 - an edge INTO the first component that
// must never merge the two. Because the DFS root order is now
// sort.Strings(groupDNMap keys), not Go's randomized map iteration, "a-"
// always sorts before "p-": the {a-cycle-1, a-cycle-2} component is always
// fully closed, and every one of its nodes popped off the Tarjan stack,
// before the DFS walks p-cycle-1's edge into a-cycle-1. A DFS that leaves a
// popped node's onStack flag stuck true, or that treats any already-visited
// node as if it were still on the current path, mistakes that stale edge
// for a back-edge: p-cycle-1's lowlink gets dragged down to a-cycle-1's
// index, p-cycle-1 is never recognised as an SCC root, and {p-cycle-1,
// p-cycle-2} never closes - 2 groups fire instead of 4. Played across all
// 24 permutations of data.Groups order: the sorted internal traversal makes
// the outcome identical regardless of input order.
func TestCircularNesting_ComponentFinishedBeforeSharedEdgeAllOrders(t *testing.T) {
	base := []types.Group{
		{DN: cnGroupACycle1, SAMAccountName: "ACycle1", MemberOf: []string{cnGroupACycle2}},
		{DN: cnGroupACycle2, SAMAccountName: "ACycle2", MemberOf: []string{cnGroupACycle1}},
		{DN: cnGroupPCycle1, SAMAccountName: "PCycle1", MemberOf: []string{cnGroupPCycle2, cnGroupACycle1}},
		{DN: cnGroupPCycle2, SAMAccountName: "PCycle2", MemberOf: []string{cnGroupPCycle1}},
	}
	for _, perm := range permutations4() {
		ordered := []types.Group{base[perm[0]], base[perm[1]], base[perm[2]], base[perm[3]]}
		f := cnDetect(t, ordered)
		if f.Count != 4 {
			t.Fatalf("order %v: expected both disjoint 2-node components (4 groups total), got count=%d", perm, f.Count)
		}
		names := map[string]bool{}
		for _, e := range f.AffectedEntities {
			names[e.Name] = true
		}
		for _, want := range []string{"ACycle1", "ACycle2", "PCycle1", "PCycle2"} {
			if !names[want] {
				t.Fatalf("order %v: expected %s among affected entities, got %v", perm, want, names)
			}
		}
	}
}
