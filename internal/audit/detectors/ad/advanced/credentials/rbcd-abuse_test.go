package credentials

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// rbcdAbuseNonEmptySD is a literal placeholder byte slice standing in for a
// real msDS-AllowedToActOnBehalfOfOtherIdentity security descriptor:
// rbcd-abuse.go has no GUID or mask constant to collide with, only a length
// check, so any fixed non-empty slice distinct from "nil" exercises the same
// boundary.
var rbcdAbuseNonEmptySD = []byte{0x01, 0x00, 0x04, 0x80, 0x11, 0x22, 0x33, 0x44}

// TestRBCDAbuse_LabPlantWitnesses mirrors exactly the 2 lab plant computers
// from docs/security-validation/results/rbcd-abuse-v2/VERDICT.md: t526pos
// carries a non-empty msDS-AllowedToActOnBehalfOfOtherIdentity, is disabled,
// and DOES fire; t526ok is also disabled but carries no attribute and does
// NOT fire - proving the detector has no guard on account state.
func TestRBCDAbuse_LabPlantWitnesses(t *testing.T) {
	t526pos := types.Computer{
		DN:                                  "CN=t526pos,OU=T526Plants,DC=example,DC=com",
		SAMAccountName:                      "t526pos$",
		Disabled:                            true,
		AllowedToActOnBehalfOfOtherIdentity: rbcdAbuseNonEmptySD,
	}
	t526ok := types.Computer{
		DN:             "CN=t526ok,OU=T526Plants,DC=example,DC=com",
		SAMAccountName: "t526ok$",
		Disabled:       true,
	}

	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers:      []types.Computer{t526pos, t526ok},
	}

	findings := NewRBCDAbuseDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (t526pos only - t526ok, disabled and attribute-free, must not fire)", f.Count)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].DN != t526pos.DN {
		t.Fatalf("AffectedEntities = %v, want only %q", f.AffectedEntities, t526pos.DN)
	}
}

// TestRBCDAbuse_EmptyNonNilSliceDoesNotFire guards the exact boundary the
// detector relies on: an explicitly non-nil but zero-length slice (as a
// provider could plausibly return instead of nil) must behave identically
// to an absent attribute.
func TestRBCDAbuse_EmptyNonNilSliceDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=empty,DC=example,DC=com", AllowedToActOnBehalfOfOtherIdentity: []byte{}},
		},
	}
	findings := NewRBCDAbuseDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 for an explicit zero-length (non-nil) slice", findings[0].Count)
	}
}

// TestRBCDAbuse_MutationCoverage is the LITERAL fixture the length check in
// rbcd-abuse.go is proven against by a temporary, uncommitted edit of that
// file (condition removed), run, and revert cycle. One computer carries a
// non-empty attribute, one does not:
//   - correct code (`> 0`): only withSD fires, Count == 1.
//   - condition dropped (unconditional append): both fire, Count == 2.
func TestRBCDAbuse_MutationCoverage(t *testing.T) {
	withSD := types.Computer{DN: "CN=withsd,DC=example,DC=com", AllowedToActOnBehalfOfOtherIdentity: rbcdAbuseNonEmptySD}
	withoutSD := types.Computer{DN: "CN=withoutsd,DC=example,DC=com"}

	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers:      []types.Computer{withSD, withoutSD},
	}
	findings := NewRBCDAbuseDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want exactly 1 (withSD only) - kills the condition-removed mutation (both fire, Count=2)", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].DN != withSD.DN {
		t.Fatalf("AffectedEntities = %v, want only %q", findings[0].AffectedEntities, withSD.DN)
	}
}

// TestRBCDAbuse_TypeSeverityCategoryLiteral pins the finding's static
// fields against LITERAL strings, not against the detector's own
// constants.
func TestRBCDAbuse_TypeSeverityCategoryLiteral(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=withsd,DC=example,DC=com", AllowedToActOnBehalfOfOtherIdentity: rbcdAbuseNonEmptySD},
		},
	}
	findings := NewRBCDAbuseDetector().Detect(context.Background(), data)
	if got := findings[0].Type; got != "RBCD_ABUSE" {
		t.Fatalf("expected Type literal \"RBCD_ABUSE\", got %q", got)
	}
	if got := string(findings[0].Severity); got != "critical" {
		t.Fatalf("expected Severity literal \"critical\", got %q", got)
	}
	if got := findings[0].Category; got != "advanced" {
		t.Fatalf("expected Category literal \"advanced\", got %q", got)
	}
}
