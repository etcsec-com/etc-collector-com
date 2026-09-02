package devices

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// EncryptionNotEnforcedDetector detects devices without disk encryption
type EncryptionNotEnforcedDetector struct {
	audit.BaseDetector
}

// NewEncryptionNotEnforcedDetector creates a new detector
func NewEncryptionNotEnforcedDetector() *EncryptionNotEnforcedDetector {
	return &EncryptionNotEnforcedDetector{
		BaseDetector: audit.NewBaseDetector("DEVICE_ENCRYPTION_NOT_ENFORCED", audit.CategoryDeviceCompliance),
	}
}

// Detect checks for devices without encryption
func (d *EncryptionNotEnforcedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// TODO: Implement when Intune provider is connected
	// Will check compliance policies for BitLocker/FileVault requirements
	// and device encryption status via managedDevice properties

	return []types.Finding{{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Device Encryption Not Enforced",
		Description: "Managed devices without disk encryption requirements. Unencrypted devices risk data exposure if lost or stolen.",
		Count:       0,
	}}
}

func init() {
	audit.MustRegister(NewEncryptionNotEnforcedDetector())
}
