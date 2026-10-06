package security

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestACLAbuse_LabPlantWitnesses mirrors exactly the 2 lab plant computers
// from docs/security-validation/results/computer-acl-abuse-v2/VERDICT.md:
// t532pos carries DangerousACL=true (disabled), and DOES fire; t532ok is
// also disabled but carries DangerousACL=false and does NOT fire - proving
// the detector has no guard on account state (DangerousACL alone decides).
func TestACLAbuse_LabPlantWitnesses(t *testing.T) {
	t532pos := types.Computer{
		DN:             "CN=t532pos,OU=T532Plants,DC=example,DC=com",
		SAMAccountName: "t532pos$",
		Disabled:       true,
		DangerousACL:   true,
	}
	t532ok := types.Computer{
		DN:             "CN=t532ok,OU=T532Plants,DC=example,DC=com",
		SAMAccountName: "t532ok$",
		Disabled:       true,
		DangerousACL:   false,
	}

	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers:      []types.Computer{t532pos, t532ok},
	}

	findings := NewACLAbuseDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (t532pos only - t532ok, disabled and DangerousACL=false, must not fire)", f.Count)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].DN != t532pos.DN {
		t.Fatalf("AffectedEntities = %v, want only %q", f.AffectedEntities, t532pos.DN)
	}
}

// TestACLAbuse_MutationCoverage is the LITERAL fixture the boolean check in
// acl-abuse.go is proven against by a temporary, uncommitted edit of that
// file (condition removed), run, and revert cycle. One computer carries
// DangerousACL=true, one carries DangerousACL=false:
//   - correct code (`if c.DangerousACL`): only the true one fires, Count == 1.
//   - condition dropped (unconditional append): both fire, Count == 2.
func TestACLAbuse_MutationCoverage(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=dangerous,DC=example,DC=com", DangerousACL: true},
			{DN: "CN=safe,DC=example,DC=com", DangerousACL: false},
		},
	}
	findings := NewACLAbuseDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want exactly 1 (DangerousACL=true only) - kills the condition-removed mutation (both fire, Count=2)", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].DN != "CN=dangerous,DC=example,DC=com" {
		t.Fatalf("AffectedEntities = %v, want only the DangerousACL=true computer", findings[0].AffectedEntities)
	}
}

// TestACLAbuse_TypeSeverityCategoryLiteral pins the finding's static
// fields against LITERAL strings, not against the detector's own
// constants.
func TestACLAbuse_TypeSeverityCategoryLiteral(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=dangerous,DC=example,DC=com", DangerousACL: true},
		},
	}
	findings := NewACLAbuseDetector().Detect(context.Background(), data)
	if got := findings[0].Type; got != "COMPUTER_ACL_ABUSE" {
		t.Fatalf("expected Type literal \"COMPUTER_ACL_ABUSE\", got %q", got)
	}
	if got := string(findings[0].Severity); got != "high" {
		t.Fatalf("expected Severity literal \"high\", got %q", got)
	}
	if got := findings[0].Category; got != "computers" {
		t.Fatalf("expected Category literal \"computers\", got %q", got)
	}
}

// TestACLAbuse_NoDangerousComputersFindsNothing guards the zero case
// explicitly: a non-empty Computers slice where none carry DangerousACL
// must produce Count=0, not merely "no panic".
func TestACLAbuse_NoDangerousComputersFindsNothing(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=a,DC=example,DC=com", DangerousACL: false},
			{DN: "CN=b,DC=example,DC=com", DangerousACL: false},
		},
	}
	findings := NewACLAbuseDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 when no computer carries DangerousACL=true", findings[0].Count)
	}
}
