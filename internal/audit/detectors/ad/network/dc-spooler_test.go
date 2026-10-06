package network

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func detectDcSpooler(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewDcSpoolerDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// TestDcSpooler_UndeterminedIsNotAffected is RED on the pre-fix detector: it
// only ever checked result.SpoolerRunning, which the old probe set to true
// for any DC with SMB reachable. After the fix, a probe result that could
// not be verified (Determined=false) must never count toward Count or
// affectedDCs.
func TestDcSpooler_UndeterminedIsNotAffected(t *testing.T) {
	f := detectDcSpooler(t, &audit.DetectorData{
		IncludeDetails: true,
		NetworkProbes: &types.NetworkProbeResults{
			SpoolerResults: []types.SpoolerProbeResult{
				{DCHostname: "dc1.example.com", SpoolerRunning: false, Determined: false, Error: "inconclusive"},
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
		t.Error("affectedDCs must be absent when nothing was confirmed running")
	}
}

func TestDcSpooler_ConfirmedRunningIsAffected(t *testing.T) {
	f := detectDcSpooler(t, &audit.DetectorData{
		IncludeDetails: true,
		NetworkProbes: &types.NetworkProbeResults{
			SpoolerResults: []types.SpoolerProbeResult{
				{DCHostname: "dc1.example.com", SpoolerRunning: true, Determined: true},
				{DCHostname: "dc2.example.com", SpoolerRunning: false, Determined: true},
			},
		},
	})
	if f.Count != 1 {
		t.Fatalf("expected count=1 for the one confirmed-running DC, got %d", f.Count)
	}
	affected, _ := f.Details["affectedDCs"].([]string)
	if len(affected) != 1 || affected[0] != "dc1.example.com" {
		t.Errorf("expected affectedDCs=[dc1.example.com], got %v", f.Details["affectedDCs"])
	}
	if _, ok := f.Details["notDetermined"]; ok {
		t.Error("notDetermined must be absent when every result was determined")
	}
}

func TestDcSpooler_NoProbeData(t *testing.T) {
	f := detectDcSpooler(t, &audit.DetectorData{IncludeDetails: true})
	if f.Count != 0 {
		t.Fatalf("no network probe data must not be reported as affected, count=%d", f.Count)
	}
}
