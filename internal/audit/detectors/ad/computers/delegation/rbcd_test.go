package delegation

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// rbcdNonEmptySD is a literal placeholder byte slice standing in for a real
// msDS-AllowedToActOnBehalfOfOtherIdentity security descriptor: rbcd.go has
// no GUID or mask constant to collide with, only a length check, so any
// fixed non-empty slice distinct from "nil" exercises the same boundary.
var rbcdNonEmptySD = []byte{0x01, 0x00, 0x04, 0x80, 0xAA, 0xBB, 0xCC, 0xDD}

// TestRbcd_LabPlantWitnesses mirrors exactly the 3 lab plant computers from
// docs/security-validation/results/computer-rbcd-v2/VERDICT.md: comp1 carries
// a non-empty msDS-AllowedToActOnBehalfOfOtherIdentity and DOES fire, comp2
// is vanilla (attribute never set, nil at read time) and does NOT fire, and
// comp3 was created with the attribute then had it removed (also nil at
// measurement time) and does NOT fire either - proving the detector reads
// only current state, never creation history.
func TestRbcd_LabPlantWitnesses(t *testing.T) {
	comp1 := types.Computer{DN: "CN=t518comp1,OU=T518Plants,DC=example,DC=com", SAMAccountName: "t518comp1$", AllowedToActOnBehalfOfOtherIdentity: rbcdNonEmptySD}
	comp2 := types.Computer{DN: "CN=t518comp2,OU=T518Plants,DC=example,DC=com", SAMAccountName: "t518comp2$"}
	comp3 := types.Computer{DN: "CN=t518comp3,OU=T518Plants,DC=example,DC=com", SAMAccountName: "t518comp3$"}

	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers:      []types.Computer{comp1, comp2, comp3},
	}

	findings := NewRbcdDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (comp1 only - comp2 vanilla and comp3 post-removal must not fire)", f.Count)
	}
	if f.Severity != types.SeverityCritical {
		t.Fatalf("Severity = %v, want Critical", f.Severity)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].DN != comp1.DN {
		t.Fatalf("AffectedEntities = %v, want only %q", f.AffectedEntities, comp1.DN)
	}
}

// TestRbcd_EmptyNonNilSliceDoesNotFire guards the exact boundary the
// detector relies on: an explicitly non-nil but zero-length slice (as a
// provider could plausibly return instead of nil) must behave identically
// to an absent attribute.
func TestRbcd_EmptyNonNilSliceDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=empty,DC=example,DC=com", AllowedToActOnBehalfOfOtherIdentity: []byte{}},
		},
	}
	findings := NewRbcdDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 for an explicit zero-length (non-nil) slice", findings[0].Count)
	}
}

// TestRbcd_MutationCoverage is the fixture three boundary mutations of the
// length check in rbcd.go are proven against by a temporary, uncommitted
// edit of that file, run, and revert cycle: the condition weakened,
// inverted, and dropped entirely. One computer carries a non-empty
// attribute, one does not:
//   - correct code (`> 0`): only withSD fires, Count == 1.
//   - M1 (`> 0` weakened to `>= 0`): both fire, Count == 2.
//   - M2 (`> 0` inverted to `== 0`): only withoutSD fires, Count == 1 but the
//     wrong DN.
//   - M3 (condition dropped, unconditional append): both fire, Count == 2.
func TestRbcd_MutationCoverage(t *testing.T) {
	withSD := types.Computer{DN: "CN=withsd,DC=example,DC=com", AllowedToActOnBehalfOfOtherIdentity: rbcdNonEmptySD}
	withoutSD := types.Computer{DN: "CN=withoutsd,DC=example,DC=com"}

	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers:      []types.Computer{withSD, withoutSD},
	}
	findings := NewRbcdDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want exactly 1 (withSD only) - kills M1 (>=0, both fire, Count=2) and M3 (condition dropped, both fire, Count=2)", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].DN != withSD.DN {
		t.Fatalf("AffectedEntities = %v, want only %q - kills M2 (==0 inversion, withoutSD would fire instead of withSD)", findings[0].AffectedEntities, withSD.DN)
	}
}
