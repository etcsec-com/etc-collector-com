package legacyauth

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDDeviceCode       = "DEVICE_CODE_FLOW_ENABLED"
	CategoryDeviceCode = audit.CategoryIdentity
)

// DeviceCodeDetector checks if device code flow is enabled
type DeviceCodeDetector struct {
	audit.BaseDetector
}

// NewDeviceCodeFlowDetector creates a new device code flow detector
func NewDeviceCodeFlowDetector() *DeviceCodeDetector {
	return &DeviceCodeDetector{
		BaseDetector: audit.NewBaseDetector(IDDeviceCode, CategoryDeviceCode),
	}
}

// Detect reports when no enabled Conditional Access policy blocks the
// device code authentication flow (a flow commonly abused in phishing).
//
// There is no tenant-wide "device code flow enabled" switch in Entra - the
// only real control is a CA policy condition (conditions.authenticationFlows
// .transferMethods = deviceCodeFlow) paired with a block grant control, the
// same thing BL_BLOCK_DEVICE_CODE_FLOW checks (see
// audit.DeviceCodeFlowBlockingPolicy, shared by both). Silent (Count 0) when
// CA policy detail was never collected: an unknown state must never be
// reported as either a finding or a clean bill of health.
func (d *DeviceCodeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDDeviceCode,
		Severity:    types.SeverityHigh,
		Category:    string(CategoryDeviceCode),
		Title:       "Device Code Flow Not Blocked",
		Description: "No enabled Conditional Access policy blocks the device code authentication flow. This flow is commonly used in phishing attacks.",
		Count:       0,
	}

	if data.AzureConditionalAccessPolicyDetails == nil {
		return []types.Finding{finding}
	}
	if data.AzureTenantConfig != nil && data.AzureTenantConfig.SecurityDefaults != nil && data.AzureTenantConfig.SecurityDefaults.IsEnabled {
		return []types.Finding{finding}
	}
	if _, blocked := audit.DeviceCodeFlowBlockingPolicy(data.AzureConditionalAccessPolicyDetails); !blocked {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDeviceCodeFlowDetector())
}
