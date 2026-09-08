package detection

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestUserRiskLowThreshold_HighOnlyMatchesMicrosoftRecommendation
// reproduces the ecart: Microsoft's own documented recommendation for the
// user risk policy is to select "High" alone (Microsoft Learn, "Risk
// policies - Microsoft Entra ID Protection", section "Microsoft
// recommendations" > "User risk policy"). Before the fix, a policy
// configured exactly that way was wrongly flagged as having too low a
// threshold.
func TestUserRiskLowThreshold_HighOnlyMatchesMicrosoftRecommendation(t *testing.T) {
	d := NewUserRiskLowThresholdDetector()
	data := &audit.DetectorData{
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{DisplayName: "user-risk-high-only", State: "enabled", UserRiskLevels: []string{"high"}},
		},
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0: 'high' alone is Microsoft's own recommended user risk policy configuration, got %d", f.Count)
	}
}

// TestUserRiskLowThreshold_MissingHighIsFlagged covers the actual gap the
// source supports: a user-risk policy that never reaches "high" falls short
// of Microsoft's recommended configuration.
func TestUserRiskLowThreshold_MissingHighIsFlagged(t *testing.T) {
	d := NewUserRiskLowThresholdDetector()
	data := &audit.DetectorData{
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{DisplayName: "user-risk-medium-only", State: "enabled", UserRiskLevels: []string{"low", "medium"}},
		},
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1: a user risk policy that never covers 'high' falls short of Microsoft's recommended configuration, got %d", f.Count)
	}
}
