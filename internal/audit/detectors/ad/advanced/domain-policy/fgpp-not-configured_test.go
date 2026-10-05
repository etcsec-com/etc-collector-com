package domainpolicy

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// FGPP_NOT_CONFIGURED is a domain-wide, inverse-polarity detector: it fires
// when NO fine-grained password policy exists at all, regardless of whether
// any existing PSO is applied to anyone or targets Tier 0. It therefore stays
// silent as soon as a single orphan PSO exists - see the v2 validation
// VERDICT for the measured false negative this produces, cross-checked
// against ANSSI_R40_NO_PSO_TIER0 and SERVICE_ACCOUNT_WEAK_PASSWORD_POLICY,
// the two other data.FGPPs readers, which both key on AppliesTo instead.
func TestFGPPNotConfigured(t *testing.T) {
	tests := []struct {
		name         string
		fgpps        []types.FGPP
		wantCount    int
		wantSeverity types.Severity
	}{
		{
			name:         "no PSO at all fires",
			fgpps:        nil,
			wantCount:    1,
			wantSeverity: types.SeverityMedium,
		},
		{
			name: "one PSO applied to nobody silences the detector",
			fgpps: []types.FGPP{
				{
					DN:                    "CN=Fixture-PSO-1,CN=Password Settings Container,CN=System,DC=example,DC=com",
					Name:                  "Fixture-PSO-1",
					Precedence:            5,
					MinPasswordLength:     12,
					PasswordHistoryLength: 6,
					LockoutThreshold:      3,
				},
			},
			wantCount:    0,
			wantSeverity: types.SeverityMedium,
		},
		{
			name: "two PSOs also silence the detector",
			fgpps: []types.FGPP{
				{
					DN:                    "CN=Fixture-PSO-1,CN=Password Settings Container,CN=System,DC=example,DC=com",
					Name:                  "Fixture-PSO-1",
					Precedence:            5,
					MinPasswordLength:     12,
					PasswordHistoryLength: 6,
					LockoutThreshold:      3,
				},
				{
					DN:                    "CN=Fixture-PSO-2,CN=Password Settings Container,CN=System,DC=example,DC=com",
					Name:                  "Fixture-PSO-2",
					Precedence:            10,
					MinPasswordLength:     8,
					PasswordHistoryLength: 3,
					LockoutThreshold:      5,
				},
			},
			wantCount:    0,
			wantSeverity: types.SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &audit.DetectorData{FGPPs: tt.fgpps}
			findings := NewFGPPNotConfiguredDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding from Detect (Count-based filtering happens in the engine, not here), got %d", len(findings))
			}
			if findings[0].Count != tt.wantCount {
				t.Fatalf("Count = %d, want %d", findings[0].Count, tt.wantCount)
			}
			if findings[0].Severity != tt.wantSeverity {
				t.Fatalf("Severity = %q, want %q", findings[0].Severity, tt.wantSeverity)
			}
		})
	}
}
