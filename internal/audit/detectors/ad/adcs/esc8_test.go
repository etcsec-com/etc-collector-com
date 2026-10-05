package adcs

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func detectESC8(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewESC8Detector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// TestESC8_UndeterminedIsNotAffected is RED on the pre-fix detector: it only
// ever checked r.WebEnrollment, so a probe that never reached the host
// (hostname unresolved) reported the same Count=0 as a real "not exposed"
// negative. After the fix, an undetermined host must be surfaced separately
// and never counted as vulnerable.
func TestESC8_UndeterminedIsNotAffected(t *testing.T) {
	f := detectESC8(t, &audit.DetectorData{
		NetworkProbes: &types.NetworkProbeResults{
			ESC8Results: []types.ESC8ProbeResult{
				{CAHostname: "dc1.example.com", WebEnrollment: false, Determined: false, Error: "DNS resolution failed"},
			},
		},
	})
	if f.Count != 0 {
		t.Fatalf("an undetermined host must not be counted as vulnerable, count=%d", f.Count)
	}
	notDetermined, _ := f.Details["notDetermined"].([]string)
	if len(notDetermined) != 1 || notDetermined[0] != "dc1.example.com" {
		t.Errorf("expected dc1.example.com to be surfaced as notDetermined, got %v", f.Details["notDetermined"])
	}
	if _, ok := f.Details["vulnerableEndpoints"]; ok {
		t.Error("vulnerableEndpoints must be absent when nothing was confirmed exposed")
	}
}

func TestESC8_ConfirmedExposedIsAffected(t *testing.T) {
	f := detectESC8(t, &audit.DetectorData{
		NetworkProbes: &types.NetworkProbeResults{
			ESC8Results: []types.ESC8ProbeResult{
				{CAHostname: "dc1.example.com", WebEnrollment: true, Determined: true, StatusCode: 200},
				{CAHostname: "dc2.example.com", WebEnrollment: false, Determined: true, StatusCode: 404},
			},
		},
	})
	if f.Count != 1 {
		t.Fatalf("expected count=1 for the one confirmed-exposed host, got %d", f.Count)
	}
	if _, ok := f.Details["notDetermined"]; ok {
		t.Error("notDetermined must be absent when every result was determined")
	}
}

func TestESC8_NoProbeData(t *testing.T) {
	f := detectESC8(t, &audit.DetectorData{})
	if f.Count != 0 {
		t.Fatalf("no network probe data must not be reported as vulnerable, count=%d", f.Count)
	}
}
