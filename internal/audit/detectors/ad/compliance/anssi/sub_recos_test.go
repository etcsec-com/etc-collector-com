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

// --- R15.1 (real controls: R56/R57) ---
//
// The previous implementation flagged an EMPTY "Allowed RODC Password
// Replication Group" as non-compliant when an RODC exists. That's backwards
// per R57's own text: an empty allow list is the safe default. This test
// would have FAILED against the old implementation (empty allow list would
// have produced Count=1 even though both Tier 0 groups sit in the deny
// list) and passes against the fix (deny-list presence is what's checked).
func TestR151RODCNoAllowedRepl_EmptyAllowListButDenyListCorrect_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{{SAMAccountName: "RODC01$", IsRODC: true}},
		Groups: []types.Group{
			{SAMAccountName: "Allowed RODC Password Replication Group", Members: nil},
			{SAMAccountName: "Denied RODC Password Replication Group", Members: []string{
				"CN=Domain Admins,CN=Users,DC=test,DC=local",
				"CN=Enterprise Admins,CN=Users,DC=test,DC=local",
				"CN=Schema Admins,CN=Users,DC=test,DC=local",
			}},
		},
	}
	d := NewR151RODCNoAllowedReplDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected no violation (deny list correctly populated despite an empty allow list), got %+v", findings)
	}
}

func TestR151RODCNoAllowedRepl_T0GroupMissingFromDenyList_Flagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{{SAMAccountName: "RODC01$", IsRODC: true}},
		Groups: []types.Group{
			{SAMAccountName: "Denied RODC Password Replication Group", Members: []string{
				"CN=Domain Admins,CN=Users,DC=test,DC=local",
				// Enterprise Admins and Schema Admins removed from the deny list.
			}},
		},
	}
	d := NewR151RODCNoAllowedReplDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 2 {
		t.Fatalf("expected 2 missing Tier 0 groups flagged, got %+v", findings)
	}
	if strings.Contains(findings[0].Title, "R15.1") || strings.Contains(findings[0].Description, "R15.1") {
		t.Errorf("finding should not cite the nonexistent PA-099 R15.1 sub-reco, got title=%q desc=%q", findings[0].Title, findings[0].Description)
	}
	if !strings.Contains(findings[0].Description, "R57") {
		t.Errorf("description should cite the real source R57, got %q", findings[0].Description)
	}
}

func TestR151RODCNoAllowedRepl_NoRODC_NA(t *testing.T) {
	data := &audit.DetectorData{Computers: []types.Computer{{SAMAccountName: "WKS01$"}}}
	d := NewR151RODCNoAllowedReplDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected N/A (no RODC), got %+v", findings)
	}
}

// --- R29.1 (real control: R25+, outgoing trusts only) ---
//
// The previous implementation counted every non-selective-auth forest
// trust regardless of direction. R25+'s text is explicitly scoped to
// outgoing ("sortantes") trusts. This test would have FAILED against the
// old implementation (an inbound-only forest trust would have been
// counted) and passes against the fix (inbound-only trusts are excluded).
func TestR291ForestTrustNoSelAuth_InboundOnly_NotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TargetDomain: "inbound.example.com", TrustType: "Forest", TrustDirection: "Inbound", SelectiveAuth: false},
		},
	}
	d := NewR291ForestTrustNoSelAuthDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected inbound-only forest trust to be out of R25+'s scope, got %+v", findings)
	}
}

func TestR291ForestTrustNoSelAuth_Outbound_Flagged(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TargetDomain: "outbound.example.com", TrustType: "Forest", TrustDirection: "Outbound", SelectiveAuth: false},
		},
	}
	d := NewR291ForestTrustNoSelAuthDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected outbound forest trust without selective auth to be flagged, got %+v", findings)
	}
	if strings.Contains(findings[0].Title, "R29.1") || strings.Contains(findings[0].Description, "R29.1") {
		t.Errorf("finding should not cite the nonexistent PA-099 R29.1 sub-reco, got title=%q desc=%q", findings[0].Title, findings[0].Description)
	}
}

func TestR291ForestTrustNoSelAuth_BidirectionalWithSelectiveAuth_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TargetDomain: "both.example.com", TrustType: "Forest", TrustDirection: "Bidirectional", SelectiveAuth: true},
		},
	}
	d := NewR291ForestTrustNoSelAuthDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected compliant bidirectional trust to be clean, got %+v", findings)
	}
}
