package gpo

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Branch 2 (fallback, no SYSVOL scan data): GPO.DisplayName (falling back to CN
// when DisplayName is empty) is matched case-insensitively against riskyPatterns.
func TestPasswordInSysvol_FallbackPatternMatch(t *testing.T) {
	cases := []struct {
		name      string
		gpos      []types.GPO
		wantCount int
	}{
		{
			name:      "DisplayName contains password -> matches",
			gpos:      []types.GPO{{DisplayName: "T530-password-test"}},
			wantCount: 1,
		},
		{
			name:      "DisplayName without any pattern -> no match",
			gpos:      []types.GPO{{DisplayName: "T530-neutral"}},
			wantCount: 0,
		},
		{
			name:      "mixed case pattern still matches",
			gpos:      []types.GPO{{DisplayName: "Local Admin Rollout"}},
			wantCount: 1,
		},
		{
			name:      "empty DisplayName falls back to CN",
			gpos:      []types.GPO{{DisplayName: "", CN: "Service Account Policy"}},
			wantCount: 1,
		},
		{
			name: "two risky + one neutral -> only risky counted",
			gpos: []types.GPO{
				{DisplayName: "Credential Rotation"},
				{DisplayName: "Drive Map Logon Script"},
				{DisplayName: "Default Domain Policy"},
			},
			wantCount: 2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{GPOs: tc.gpos}

			findings := NewPasswordInSysvolDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Fatalf("Count = %d, want %d", findings[0].Count, tc.wantCount)
			}
		})
	}
}

// Branch 1 (real SYSVOL scan with an actual cpassword hit) takes priority over
// the branch 2 fallback and short-circuits before the GPO name scan runs.
func TestPasswordInSysvol_CpasswordBranchTakesPriority(t *testing.T) {
	data := &audit.DetectorData{
		SYSVOLFindings: []audit.SYSVOLFinding{
			{Type: "cpassword", GPOName: "Legacy Mapped Drive", GPOGUID: "{GUID}", Details: "Groups.xml cpassword found"},
		},
		GPOs: []types.GPO{
			{DisplayName: "Default Domain Policy"}, // no risky pattern; must not affect branch 1's count
		},
	}

	findings := NewPasswordInSysvolDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (cpassword branch)", findings[0].Count)
	}
}

// MUTATION M1 - a restaurer: removing the `for _, pattern := range riskyPatterns`
// loop or its `strings.Contains(gpoName, pattern)` condition in password-in-sysvol.go
// must make this test fail (Count goes from 1 to 0). Fixture values are literal
// strings distinct from the detector's riskyPatterns slice contents, so the test
// cannot pass by construction alone.
func TestPasswordInSysvol_MutationM1_PatternMatchRequired(t *testing.T) {
	data := &audit.DetectorData{
		GPOs: []types.GPO{
			{DisplayName: "test-password"},
			{DisplayName: "test-neutral"},
		},
	}

	findings := NewPasswordInSysvolDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (only test-password should match, test-neutral must not)", findings[0].Count)
	}
}
