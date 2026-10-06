package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// The previous implementation matched "srp " (with a trailing space),
// which misses any GPO whose name literally ends in "SRP" (no trailing
// character). This test would have FAILED against the old implementation
// (hasHint stays false, GPO treated as non-hinting) and passes against the
// fix (trailing-space requirement dropped).
func TestR37AppLocker_GPONameEndingInSRP_Recognized(t *testing.T) {
	data := &audit.DetectorData{
		GPOs: []types.GPO{{DisplayName: "Legacy SRP"}},
	}
	d := NewR37AppLockerHeuristicDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected a GPO named 'Legacy SRP' to be recognized as an AppLocker/SRP hint, got %+v", findings)
	}
}

func TestR37AppLocker_NoHintingGPO_Flagged(t *testing.T) {
	data := &audit.DetectorData{
		GPOs: []types.GPO{{DisplayName: "Default Domain Policy"}},
	}
	d := NewR37AppLockerHeuristicDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected no AppLocker/WDAC hint to be flagged, got %+v", findings)
	}
}
