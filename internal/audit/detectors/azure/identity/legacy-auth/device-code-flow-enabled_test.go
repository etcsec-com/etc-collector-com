package legacyauth

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DEVICE_CODE_FLOW_ENABLED read data.AzureTenantConfig.DeviceCodeFlowEnabled,
// a field fed by a Graph call to /policies/authenticationFlowsPolicy - a
// resource that has no deviceCodeAuthenticationConfiguration property in
// either v1.0 or beta, so the field could never become anything but false
// and the detector never fired a true positive. The real signal is a
// Conditional Access policy condition (authenticationFlows.transferMethods),
// exposed on AzureConditionalAccessPolicyDetails.

func deviceCodeFlowCondition() json.RawMessage {
	return json.RawMessage(`{"transferMethods":"deviceCodeFlow"}`)
}

func TestDeviceCodeFlow_NoDetailDoesNotGuess(t *testing.T) {
	data := &audit.DetectorData{}
	f := NewDeviceCodeFlowDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 (unknown, no verdict) when CA policy detail was never collected, got %d", f.Count)
	}
}

func TestDeviceCodeFlow_DetailCollectedNoBlockingPolicy_Fires(t *testing.T) {
	data := &audit.DetectorData{
		AzureConditionalAccessPolicyDetails: []types.ConditionalAccessPolicyDetail{
			{ID: "ca-1", State: "enabled", GrantControls: &types.CADetailGrantControls{BuiltInControls: []string{"mfa"}}},
		},
	}
	f := NewDeviceCodeFlowDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 when CA detail was collected but no policy blocks device code flow, got %d", f.Count)
	}
}

func TestDeviceCodeFlow_EnabledBlockingPolicyClearsFinding(t *testing.T) {
	data := &audit.DetectorData{
		AzureConditionalAccessPolicyDetails: []types.ConditionalAccessPolicyDetail{
			{
				ID:    "ca-block-devicecode",
				State: "enabled",
				Conditions: &types.CADetailConditions{
					AuthenticationFlows: deviceCodeFlowCondition(),
				},
				GrantControls: &types.CADetailGrantControls{BuiltInControls: []string{"block"}},
			},
		},
	}
	f := NewDeviceCodeFlowDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 when an enabled CA policy blocks device code flow, got %d", f.Count)
	}
}

func TestDeviceCodeFlow_DisabledBlockingPolicyDoesNotCount(t *testing.T) {
	data := &audit.DetectorData{
		AzureConditionalAccessPolicyDetails: []types.ConditionalAccessPolicyDetail{
			{
				ID:    "ca-block-devicecode-disabled",
				State: "disabled",
				Conditions: &types.CADetailConditions{
					AuthenticationFlows: deviceCodeFlowCondition(),
				},
				GrantControls: &types.CADetailGrantControls{BuiltInControls: []string{"block"}},
			},
		},
	}
	f := NewDeviceCodeFlowDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 (only a disabled policy blocks device code flow), got %d", f.Count)
	}
}

func TestDeviceCodeFlow_SecurityDefaultsShortCircuit(t *testing.T) {
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{
			SecurityDefaults: &types.TenantSecurityDefaults{IsEnabled: true},
		},
		AzureConditionalAccessPolicyDetails: []types.ConditionalAccessPolicyDetail{
			{ID: "ca-1", State: "enabled", GrantControls: &types.CADetailGrantControls{BuiltInControls: []string{"mfa"}}},
		},
	}
	f := NewDeviceCodeFlowDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 when Security Defaults are enabled regardless of CA policies, got %d", f.Count)
	}
}
