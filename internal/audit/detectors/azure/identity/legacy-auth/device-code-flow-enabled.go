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

// Detect checks if device code flow authentication is enabled
func (d *DeviceCodeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDDeviceCode,
		Severity:    types.SeverityHigh,
		Category:    string(CategoryDeviceCode),
		Title:       "Device Code Flow Enabled",
		Description: "Device code flow authentication is enabled tenant-wide. This flow is commonly used in phishing attacks.",
		Count:       0,
	}

	if data.AzureTenantConfig != nil && data.AzureTenantConfig.DeviceCodeFlowEnabled {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDeviceCodeFlowDetector())
}
