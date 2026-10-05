package gpo

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Confirms the gPCFlags=3 ("both User and Computer settings disabled")
// reading against Microsoft's documented flags values (see the citation on
// gpoFlagAllDisabled) and against the live plant/revert proof in
// docs/security-validation/results/t163-manual/VERDICT-T163.md - this is
// not a correction (the code already matched the source), but confirming
// unit coverage for flags=3 vs the three other flags states was previously
// absent from this package.
func TestDisabledButLinked_FlagsStates(t *testing.T) {
	cases := []struct {
		name      string
		flags     int
		linked    bool
		wantCount int
	}{
		{"flags=0 both enabled, linked -> not affected", 0, true, 0},
		{"flags=1 user disabled only, linked -> not affected", 1, true, 0},
		{"flags=2 computer disabled only, linked -> not affected", 2, true, 0},
		{"flags=3 all disabled, linked -> affected", 3, true, 1},
		{"flags=3 all disabled, not linked -> not affected", 3, false, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{
				GPOs: []types.GPO{
					{CN: "{GUID}", DisplayName: "Test GPO", Flags: tc.flags},
				},
				GPOLinks: []audit.GPOLink{
					{GPOCN: "{GUID}", LinkedTo: "OU=Test,DC=test,DC=local", LinkEnabled: tc.linked},
				},
			}

			findings := NewDisabledButLinkedDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Fatalf("Count = %d, want %d", findings[0].Count, tc.wantCount)
			}
		})
	}
}
