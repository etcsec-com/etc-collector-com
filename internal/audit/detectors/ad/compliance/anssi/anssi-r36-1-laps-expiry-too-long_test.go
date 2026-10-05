package anssi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// this detector's finding previously claimed "ANSSI R36.1 (sub-reco)
// requires LAPS password rotations no more than 30 days apart". PA-099 has
// no dotted sub-recommendation numbering at all, and R36 is about CA/PKI
// risk, not LAPS. The real, verified source is R30 (p.48), which requires
// automatic local-admin-password rotation but specifies no day threshold.
func TestR361LAPSExpiry_Detect(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	staleComputer := types.Computer{
		SAMAccountName:     "WKS01$",
		LAPSPasswordExpiry: now.AddDate(0, 0, 45), // 45 days out - beyond the 30-day benchmark
	}
	freshComputer := types.Computer{
		SAMAccountName:     "WKS02$",
		LAPSPasswordExpiry: now.AddDate(0, 0, 10), // within benchmark
	}
	outOfScopeComputer := types.Computer{
		SAMAccountName: "WKS03$", // no LAPS expiry set - not managed by LAPS
	}

	cases := []struct {
		name      string
		computers []types.Computer
		wantCount int
	}{
		{"no computers -> no finding", nil, 0},
		{"fresh LAPS expiry -> clean", []types.Computer{freshComputer}, 0},
		{"computer outside LAPS scope -> not flagged", []types.Computer{outOfScopeComputer}, 0},
		{"stale LAPS expiry (>30d) -> flagged", []types.Computer{staleComputer}, 1},
		{"mixed -> only stale counted", []types.Computer{freshComputer, staleComputer, outOfScopeComputer}, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{Now: now, Computers: tc.computers}
			d := NewR361LAPSExpiryDetector()
			findings := d.Detect(context.Background(), data)
			if tc.wantCount == 0 {
				if len(findings) != 0 {
					t.Fatalf("expected no finding, got %+v", findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Errorf("Count = %d, want %d", findings[0].Count, tc.wantCount)
			}
		})
	}
}

func TestR361LAPSExpiry_DoesNotClaimNonexistentANSSISubReco(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Computers: []types.Computer{
			{SAMAccountName: "WKS01$", LAPSPasswordExpiry: now.AddDate(0, 0, 45)},
		},
	}
	d := NewR361LAPSExpiryDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	title := findings[0].Title
	desc := findings[0].Description
	if strings.Contains(title, "R36.1") || strings.Contains(desc, "R36.1") {
		t.Errorf("finding still cites the nonexistent PA-099 R36.1 sub-reco: title=%q desc=%q", title, desc)
	}
	if !strings.Contains(desc, "R30") {
		t.Errorf("description should cite the real source R30, got %q", desc)
	}
	if strings.Contains(desc, "requires LAPS password rotations no more than") {
		t.Errorf("description should not claim ANSSI mandates the 30-day number, got %q", desc)
	}
}
