package gpo

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// CACHED_LOGONS_EXCESSIVE treated "no GPO sets CachedLogonsCount" as
// compliant. That is backwards: Windows' own default for an unconfigured
// Winlogon\CachedLogonsCount is 10 (Microsoft Learn, "Interactive logon:
// Number of previous logons to cache..."), which is already above the >4
// bar. The most common real-world case (nobody configured the setting) was
// exactly the case the detector silently cleared.
func TestCachedLogons_NilMeansWindowsDefaultNotCompliant(t *testing.T) {
	three := 3
	ten := 10

	cases := []struct {
		name      string
		value     *int
		wantCount int
	}{
		// nil = no GPO sets it = Windows default (10) applies = non-compliant.
		{"value=nil (Windows default 10 applies)", nil, 1},
		// Explicit value at/under the threshold is compliant.
		{"value=3 (explicit, under threshold)", &three, 0},
		// Explicit value above the threshold is non-compliant (unchanged
		// behavior, still covered so the nil fix can't quietly break it).
		{"value=10 (explicit, over threshold)", &ten, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{
				GPOPolicies: map[string]*audit.GPOPolicy{
					"GUID": {
						RegistrySettings: &audit.RegistrySettings{
							CachedLogonsCount: tc.value,
						},
					},
				},
			}

			findings := NewCachedLogonsDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Fatalf("Count = %d, want %d", findings[0].Count, tc.wantCount)
			}
		})
	}
}

// No GPO at all (empty policy map) must behave exactly like an explicit nil:
// still the Windows default of 10, still non-compliant.
func TestCachedLogons_NoGPOAtAllStillAppliesDefault(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{}}

	findings := NewCachedLogonsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (Windows default of 10 exceeds the threshold of 4)", findings[0].Count)
	}
}
