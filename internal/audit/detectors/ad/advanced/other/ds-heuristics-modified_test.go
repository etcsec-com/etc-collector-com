package other

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// [MS-ADTS] "dSHeuristics" (character table, row 3 "fDoListObject"): "If
// this character is '1', then the fDoListObject heuristic is TRUE;
// otherwise ... FALSE" (default is FALSE/"0"). List Object mode TRUE
// restricts visibility of child objects to principals holding explicit
// list rights - a hardening of object enumeration, not a weakening.
//
// The detector previously labeled dsHeuristics[2] == '1' as "List Object
// mode disabled" and filed it under dangerousSettings, inverting both the
// value (a '1' means the mode is ENABLED, not disabled) and the sense (an
// enabled List Object mode is a hardening feature, not a danger). This
// test fails against that old code (the "disabled" wording, filed as
// dangerous) and passes once the label reads "enabled" and the entry moves
// to a separate hardeningSettings bucket.
func TestDsHeuristicsModified_ListObjectModeEnabledIsHardeningNotDanger(t *testing.T) {
	d := NewDsHeuristicsModifiedDetector()

	findings := d.Detect(context.Background(), &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DsHeuristics: "001"},
	})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}

	details := findings[0].Details
	if details == nil {
		t.Fatalf("expected Details to be populated for a modified dsHeuristics value")
	}

	// Must NOT appear under dangerousSettings.
	if dangerous, ok := details["dangerousSettings"].([]string); ok {
		for _, s := range dangerous {
			if s == "List Object mode disabled (position 3)" {
				t.Fatalf("List Object mode ENABLED (dsHeuristics[2]=='1') must not be reported as a dangerous setting with an inverted 'disabled' label; got dangerousSettings=%v", dangerous)
			}
		}
	}

	// Must appear, correctly worded, under hardeningSettings.
	hardening, ok := details["hardeningSettings"].([]string)
	if !ok {
		t.Fatalf("expected Details[\"hardeningSettings\"] to be a []string, got %#v", details["hardeningSettings"])
	}
	want := "List Object mode enabled (position 3) - restricts object visibility to explicit list rights; confirm this is an intentional change"
	found := false
	for _, s := range hardening {
		if s == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected hardeningSettings to contain %q, got %v", want, hardening)
	}
}

// dsHeuristics[2] == '0' (the default) must not raise the List Object entry
// at all - it is only notable when it deviates from default.
func TestDsHeuristicsModified_ListObjectModeDefaultNotFlagged(t *testing.T) {
	d := NewDsHeuristicsModifiedDetector()

	findings := d.Detect(context.Background(), &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DsHeuristics: "0000002"},
	})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}

	if hardening, ok := findings[0].Details["hardeningSettings"]; ok {
		t.Fatalf("dsHeuristics[2]=='0' (default) must not populate hardeningSettings, got %v", hardening)
	}
}
