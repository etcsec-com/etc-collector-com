package sspr

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SSPR_NOT_ENABLED hardcoded Count=1, ignoring data entirely. The per-user
// IsSSPREnabled flag Graph returns in /reports/authenticationMethods/
// userRegistrationDetails IS already collected, just never aggregated into
// UserRegistrationStats nor read by this detector.

func TestSsprNotEnabled_AllUsersEnabled_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		AzureAuthMethodsDetail: &types.AuthMethodsDetail{
			UserRegistrationStats: &types.UserRegistrationStats{
				Total:       3,
				SSPREnabled: 3,
			},
		},
	}
	f := NewSsprNotEnabledDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (all 3 users have SSPR enabled - false positive)", f.Count)
	}
}

func TestSsprNotEnabled_PartialCoverage_CountsGap(t *testing.T) {
	data := &audit.DetectorData{
		AzureAuthMethodsDetail: &types.AuthMethodsDetail{
			UserRegistrationStats: &types.UserRegistrationStats{
				Total:       10,
				SSPREnabled: 4,
			},
		},
	}
	f := NewSsprNotEnabledDetector().Detect(context.Background(), data)[0]
	if f.Count != 6 {
		t.Fatalf("Count = %d, want 6 (10 total - 4 enabled)", f.Count)
	}
}

func TestSsprNotEnabled_NoData_NoFinding(t *testing.T) {
	data := &audit.DetectorData{}
	f := NewSsprNotEnabledDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 when no userRegistrationDetails were collected", f.Count)
	}
}
