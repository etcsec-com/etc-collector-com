package controls

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CA_TOKEN_PROTECTION_DISABLED read data.AzureConditionalAccessPolicies
// .TokenProtectionRequired, a flat field convertConditionalAccessPolicy
// never assigns, so it was always false and the detector always fired. The
// real data lives in the nested AzureConditionalAccessPolicyDetails slice
// (sessionControls.tokenProtection.isEnabled).

func TestTokenProtectionDisabled_NoDetailDoesNotGuess(t *testing.T) {
	data := &audit.DetectorData{}
	f := NewTokenProtectionDisabledDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 (no verdict) when no CA policy detail was collected, got %d", f.Count)
	}
}

func TestTokenProtectionDisabled_DetailCollectedButNoTokenProtectionFires(t *testing.T) {
	data := &audit.DetectorData{
		AzureConditionalAccessPolicyDetails: []types.ConditionalAccessPolicyDetail{
			{State: "enabled"},
		},
	}
	f := NewTokenProtectionDisabledDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 when policy detail was collected but no policy enables token protection, got %d", f.Count)
	}
}

func TestTokenProtectionDisabled_EnabledPolicyClearsFinding(t *testing.T) {
	data := &audit.DetectorData{
		AzureConditionalAccessPolicyDetails: []types.ConditionalAccessPolicyDetail{
			{
				State: "enabled",
				SessionControls: &types.CADetailSessionControls{
					TokenProtection: &types.CADetailTokenProtection{IsEnabled: true},
				},
			},
		},
	}
	f := NewTokenProtectionDisabledDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 when an enabled CA policy requires token protection, got %d", f.Count)
	}
}

func TestTokenProtectionDisabled_DisabledPolicyDoesNotCount(t *testing.T) {
	data := &audit.DetectorData{
		AzureConditionalAccessPolicyDetails: []types.ConditionalAccessPolicyDetail{
			{
				State: "disabled",
				SessionControls: &types.CADetailSessionControls{
					TokenProtection: &types.CADetailTokenProtection{IsEnabled: true},
				},
			},
		},
	}
	f := NewTokenProtectionDisabledDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 (only a disabled policy has token protection), got %d", f.Count)
	}
}
