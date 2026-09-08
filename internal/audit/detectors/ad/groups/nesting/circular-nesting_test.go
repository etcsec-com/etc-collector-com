package nesting

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	cnDomainDN = "DC=example,DC=com"
	cnGroupA   = "CN=GroupA,OU=Groups," + cnDomainDN
	cnGroupB   = "CN=GroupB,OU=Groups," + cnDomainDN
	cnGroupC   = "CN=GroupC,OU=Groups," + cnDomainDN
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
