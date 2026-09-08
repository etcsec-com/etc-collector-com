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
