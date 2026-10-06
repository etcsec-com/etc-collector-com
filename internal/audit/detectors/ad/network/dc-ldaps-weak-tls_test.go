package network

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func detectDcLdapsWeakTls(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewDcLdapsWeakTlsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// TestDcLdapsWeakTls_UndeterminedIsNotAffected is RED on the pre-fix
// detector: it only ever checked result.WeakTLS, so a probe that never
// reached the DC (hostname unresolved) reported the same Count=0 as a real
// "TLS is fine" negative. After the fix, an undetermined result must be
// surfaced separately and never counted as affected.
func TestDcLdapsWeakTls_UndeterminedIsNotAffected(t *testing.T) {
	f := detectDcLdapsWeakTls(t, &audit.DetectorData{
		IncludeDetails: true,
		NetworkProbes: &types.NetworkProbeResults{
			TLSResults: []types.TLSProbeResult{
				{DCHostname: "dc1.example.com", WeakTLS: false, Determined: false, Error: "DNS resolution failed"},
			},
		},
	})
	if f.Count != 0 {
		t.Fatalf("an undetermined DC must not be counted as affected, count=%d", f.Count)
	}
	notDetermined, _ := f.Details["notDetermined"].([]string)
	if len(notDetermined) != 1 || notDetermined[0] != "dc1.example.com" {
		t.Errorf("expected dc1.example.com to be surfaced as notDetermined, got %v", f.Details["notDetermined"])
	}
	if _, ok := f.Details["affectedDCs"]; ok {
		t.Error("affectedDCs must be absent when nothing was confirmed weak")
	}
}

func TestDcLdapsWeakTls_ConfirmedWeakIsAffected(t *testing.T) {
	f := detectDcLdapsWeakTls(t, &audit.DetectorData{
		IncludeDetails: true,
		NetworkProbes: &types.NetworkProbeResults{
			TLSResults: []types.TLSProbeResult{
				{DCHostname: "dc1.example.com", WeakTLS: true, Determined: true},
				{DCHostname: "dc2.example.com", WeakTLS: false, Determined: true},
			},
		},
	})
	if f.Count != 1 {
		t.Fatalf("expected count=1 for the one confirmed-weak DC, got %d", f.Count)
	}
	affected, _ := f.Details["affectedDCs"].([]string)
	if len(affected) != 1 || affected[0] != "dc1.example.com" {
		t.Errorf("expected affectedDCs=[dc1.example.com], got %v", f.Details["affectedDCs"])
	}
	if _, ok := f.Details["notDetermined"]; ok {
		t.Error("notDetermined must be absent when every result was determined")
	}
}

func TestDcLdapsWeakTls_NoProbeData(t *testing.T) {
	f := detectDcLdapsWeakTls(t, &audit.DetectorData{IncludeDetails: true})
	if f.Count != 0 {
		t.Fatalf("no network probe data must not be reported as affected, count=%d", f.Count)
	}
}
