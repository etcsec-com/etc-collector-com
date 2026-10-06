package devices

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DeviceComplianceMissingDetector detects devices without compliance policies
type DeviceComplianceMissingDetector struct {
	audit.BaseDetector
}

// NewDeviceComplianceMissingDetector creates a new detector
func NewDeviceComplianceMissingDetector() *DeviceComplianceMissingDetector {
	return &DeviceComplianceMissingDetector{
		BaseDetector: audit.NewBaseDetector("DEVICE_COMPLIANCE_MISSING", audit.CategoryDeviceCompliance),
	}
}

// Detect checks for devices without compliance policies
func (d *DeviceComplianceMissingDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// TODO: Implement when Intune provider is connected
	// Will query deviceCompliancePolicies and deviceCompliancePolicyStates
	// Devices with no policy assigned or non-compliant state = finding

	return []types.Finding{{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Device Compliance Policy Missing",
		Description: "Managed devices without compliance policies. Non-compliant devices may access corporate resources without meeting security requirements.",
		Count:       0,
	}}
}

func init() {
	audit.MustRegister(NewDeviceComplianceMissingDetector())
}
