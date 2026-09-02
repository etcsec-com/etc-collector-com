package mfa

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestSuspicious_NoSignals(t *testing.T) {
	d := NewMFASuspiciousActivityDetector()
	data := &audit.DetectorData{}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0, got %d", f.Count)
	}
}

func TestSuspicious_ManyIPsSameUser(t *testing.T) {
	d := NewMFASuspiciousActivityDetector()
	data := &audit.DetectorData{
		AzureRiskySignIns: []types.RiskySignIn{
			{UserPrincipalName: "a@t", IPAddress: "1.1.1.1", Location: "FR", RiskState: "atRisk"},
			{UserPrincipalName: "a@t", IPAddress: "2.2.2.2", Location: "FR", RiskState: "atRisk"},
			{UserPrincipalName: "a@t", IPAddress: "3.3.3.3", Location: "FR", RiskState: "atRisk"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1, got %d", f.Count)
	}
}

func TestSuspicious_MultiGeoSameUser(t *testing.T) {
	d := NewMFASuspiciousActivityDetector()
	data := &audit.DetectorData{
		AzureRiskySignIns: []types.RiskySignIn{
			{UserPrincipalName: "a@t", IPAddress: "1.1.1.1", Location: "FR", RiskState: "atRisk"},
			{UserPrincipalName: "a@t", IPAddress: "1.1.1.1", Location: "US", RiskState: "atRisk"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 for multi-geo, got %d", f.Count)
	}
}

func TestSuspicious_DismissedIgnored(t *testing.T) {
	d := NewMFASuspiciousActivityDetector()
	data := &audit.DetectorData{
		AzureRiskySignIns: []types.RiskySignIn{
			{UserPrincipalName: "a@t", IPAddress: "1.1.1.1", Location: "FR", RiskState: "dismissed"},
			{UserPrincipalName: "a@t", IPAddress: "2.2.2.2", Location: "US", RiskState: "dismissed"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for dismissed, got %d", f.Count)
	}
}

func TestSuspicious_HighRiskEvents(t *testing.T) {
	d := NewMFASuspiciousActivityDetector()
	data := &audit.DetectorData{
		AzureRiskySignIns: []types.RiskySignIn{
			{UserPrincipalName: "a@t", RiskLevel: "high", RiskState: "atRisk"},
			{UserPrincipalName: "a@t", RiskLevel: "high", RiskState: "atRisk"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 for high-risk events, got %d", f.Count)
	}
}

// TestSuspicious_PairsOrderIsDeterministic covers T_046/B_048 (routed from ad
// via T_049): `stats` is a map keyed by UPN, so ranging it directly to build
// Details["pairs"] gave a randomized order per process — same input, different
// JSON, different sha256 across runs. Six distinct UPNs make an accidental
// alphabetical match on any single run implausible (1/720), so five repeated
// Detect() calls asserting the exact expected order pins the sort: this test
// fails intermittently without it and passes every time with it.
//
// This is the proof T_049 asked for in place of the frozen bench, which only
// replays an LDAP thread and cannot exercise an Entra path at all.
func TestSuspicious_PairsOrderIsDeterministic(t *testing.T) {
	d := NewMFASuspiciousActivityDetector()
	// Three distinct IPs is exactly the multi-IP threshold, so every one of
	// these six users produces a "pairs" entry.
	upns := []string{"zulu@t", "yankee@t", "xray@t", "whiskey@t", "victor@t", "uniform@t"}
	var signIns []types.RiskySignIn
	for _, upn := range upns {
		signIns = append(signIns,
			types.RiskySignIn{UserPrincipalName: upn, IPAddress: "1.1.1.1", Location: "FR", RiskState: "atRisk"},
			types.RiskySignIn{UserPrincipalName: upn, IPAddress: "2.2.2.2", Location: "FR", RiskState: "atRisk"},
			types.RiskySignIn{UserPrincipalName: upn, IPAddress: "3.3.3.3", Location: "FR", RiskState: "atRisk"},
		)
	}
	data := &audit.DetectorData{AzureRiskySignIns: signIns}

	want := []string{
		"user=uniform@t signals=[3 distinct IPs]",
		"user=victor@t signals=[3 distinct IPs]",
		"user=whiskey@t signals=[3 distinct IPs]",
		"user=xray@t signals=[3 distinct IPs]",
		"user=yankee@t signals=[3 distinct IPs]",
		"user=zulu@t signals=[3 distinct IPs]",
	}

	for i := 0; i < 5; i++ {
		f := d.Detect(context.Background(), data)[0]
		if f.Count != len(upns) {
			t.Fatalf("run %d: expected %d anomalous users, got %d", i, len(upns), f.Count)
		}
		pairs, ok := f.Details["pairs"].([]string)
		if !ok {
			t.Fatalf("run %d: Details[\"pairs\"] is not []string: %#v", i, f.Details["pairs"])
		}
		if len(pairs) != len(want) {
			t.Fatalf("run %d: expected %d pairs, got %d (%v)", i, len(want), len(pairs), pairs)
		}
		for j, p := range pairs {
			if p != want[j] {
				t.Fatalf("run %d: pairs order not deterministic — position %d = %q, want %q", i, j, p, want[j])
			}
		}
	}
}
