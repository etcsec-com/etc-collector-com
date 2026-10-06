package network

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func detectDnsZoneTransfer(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewDnsZoneTransferDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// TestDnsZoneTransfer_UndeterminedIsNotAffected is RED on the pre-fix
// detector: it only ever checked zt.Allowed, so a probe that never reached
// the DC (hostname unresolved) reported the same Count=0 as a real "transfer
// denied" negative. After the fix, an undetermined zone must be surfaced
// separately and never counted as vulnerable.
func TestDnsZoneTransfer_UndeterminedIsNotAffected(t *testing.T) {
	f := detectDnsZoneTransfer(t, &audit.DetectorData{
		NetworkProbes: &types.NetworkProbeResults{
			ZoneTransfers: []types.ZoneTransferResult{
				{Zone: "example.com", Allowed: false, Determined: false, Error: "DNS resolution failed"},
			},
		},
	})
	if f.Count != 0 {
		t.Fatalf("an undetermined zone must not be counted as vulnerable, count=%d", f.Count)
	}
	notDetermined, _ := f.Details["notDetermined"].([]string)
	if len(notDetermined) != 1 || notDetermined[0] != "example.com" {
		t.Errorf("expected example.com to be surfaced as notDetermined, got %v", f.Details["notDetermined"])
	}
	if _, ok := f.Details["vulnerableZones"]; ok {
		t.Error("vulnerableZones must be absent when nothing was confirmed allowed")
	}
}

func TestDnsZoneTransfer_ConfirmedAllowedIsVulnerable(t *testing.T) {
	f := detectDnsZoneTransfer(t, &audit.DetectorData{
		NetworkProbes: &types.NetworkProbeResults{
			ZoneTransfers: []types.ZoneTransferResult{
				{Zone: "example.com", Allowed: true, Determined: true, RecordCount: 42},
				{Zone: "corp.example.com", Allowed: false, Determined: true},
			},
		},
	})
	if f.Count != 1 {
		t.Fatalf("expected count=1 for the one confirmed-allowed zone, got %d", f.Count)
	}
	vulnerable, _ := f.Details["vulnerableZones"].([]string)
	if len(vulnerable) != 1 || vulnerable[0] != "example.com" {
		t.Errorf("expected vulnerableZones=[example.com], got %v", f.Details["vulnerableZones"])
	}
	if _, ok := f.Details["notDetermined"]; ok {
		t.Error("notDetermined must be absent when every zone was determined")
	}
}

func TestDnsZoneTransfer_NoProbeData(t *testing.T) {
	f := detectDnsZoneTransfer(t, &audit.DetectorData{})
	if f.Count != 0 {
		t.Fatalf("no network probe data must not be reported as vulnerable, count=%d", f.Count)
	}
}
