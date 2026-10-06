package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R86 name-heuristic false positives ---

// TestR86AdminForestSegregation_BareSubstringsNoLongerMatch:
// adminForestNameMarkers used to include bare "red" and "t0", which match
// common unrelated substrings ("shared", "credentials" contain "red";
// "test01" contains "t0" via "st0"). Neither of these domains is an admin
// forest and neither should be flagged after the fix.
func TestR86AdminForestSegregation_BareSubstringsNoLongerMatch(t *testing.T) {
	falsePositiveDomains := []string{"shared.corp.local", "credentials.corp.local", "test01.corp.local"}
	for _, domain := range falsePositiveDomains {
		t.Run(domain, func(t *testing.T) {
			data := &audit.DetectorData{
				Trusts: []types.Trust{{TargetDomain: domain, SIDFiltering: false, SelectiveAuth: false}},
			}
			d := NewR86AdminForestSegregationDetector()
			findings := d.Detect(context.Background(), data)
			if len(findings) != 0 {
				t.Errorf("domain %q should no longer match the admin-forest heuristic, got %+v", domain, findings)
			}
		})
	}
}

// TestR86AdminForestSegregation_RealMarkerStillMatches is the regression
// check: a genuine admin-forest-looking trust name must still be flagged
// when weakly configured.
func TestR86AdminForestSegregation_RealMarkerStillMatches(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{{TargetDomain: "tier0.corp.local", SIDFiltering: false, SelectiveAuth: false}},
	}
	d := NewR86AdminForestSegregationDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count == 0 {
		t.Fatalf("expected a flagged finding for a genuine tier0-named trust, got %+v", findings)
	}
}
