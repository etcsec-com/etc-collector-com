package other

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// The unanchored "admin|root|sa" pattern matched "sa" as a bare
// substring of ordinary English words. Both real detections observed on
// live data were exactly this: false positives, not credential hints.
func TestDescriptionSensitive_WordBoundaryAnchoring(t *testing.T) {
	cases := []struct {
		name        string
		description string
		wantFlagged bool
	}{
		{"\"Disabled\" contains \"sa\" as a substring but is not sensitive", "Disabled - awaiting decommission", false},
		{"\"necessary\" contains \"ssa\" but is not sensitive", "Kept online, deemed necessary by ops", false},
		{"standalone \"sa\" token IS still a real hit", "Login: sa, contact helpdesk", true},
		{"\"admin\" as a whole word is still a real hit", "admin workstation", true},
		{"\"root\" as a whole word is still a real hit", "root access enabled", true},
		{"password keyword is unaffected by this change", "password=hunter2", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := types.Computer{DN: "CN=WKS,DC=example,DC=com", Description: tc.description}
			data := &audit.DetectorData{Computers: []types.Computer{c}}
			findings := NewDescriptionSensitiveDetector().Detect(context.Background(), data)
			gotFlagged := findings[0].Count > 0
			if gotFlagged != tc.wantFlagged {
				t.Fatalf("description %q: flagged=%v, want %v", tc.description, gotFlagged, tc.wantFlagged)
			}
		})
	}
}

// Mirrors a live lab plant: three computer objects with these exact
// description strings, cross-checked against a real audit run.
func TestDescriptionSensitive_LabPlantWitnesses(t *testing.T) {
	cases := []struct {
		name        string
		description string
		wantFlagged bool
	}{
		{"password keyword in a free-form sentence fires", "server password here", true},
		{"word-boundary anchored \"sa\" inside \"diSAbled\" still does not fire", "diSAbled server", false},
		{"clean description with no sensitive pattern does not fire", "clean deployment note", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := types.Computer{DN: "CN=WKS,DC=example,DC=com", Description: tc.description}
			data := &audit.DetectorData{Computers: []types.Computer{c}}
			findings := NewDescriptionSensitiveDetector().Detect(context.Background(), data)
			gotFlagged := findings[0].Count > 0
			if gotFlagged != tc.wantFlagged {
				t.Fatalf("description %q: flagged=%v, want %v", tc.description, gotFlagged, tc.wantFlagged)
			}
		})
	}
}

// A description matching two of the three patterns must still count its
// computer once: the loop breaks after the first pattern match.
func TestDescriptionSensitive_BreakPreventsDoubleCounting(t *testing.T) {
	c := types.Computer{DN: "CN=WKS,DC=example,DC=com", Description: "admin password reset pending"}
	data := &audit.DetectorData{Computers: []types.Computer{c}}
	findings := NewDescriptionSensitiveDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("single computer matching two patterns: Count=%d, want 1", findings[0].Count)
	}
}
