package emergency

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// EmergencyCredentialStaleDetector is an advisory detector for emergency account credential rotation
type EmergencyCredentialStaleDetector struct {
	audit.BaseDetector
}

// NewEmergencyCredentialStaleDetector creates a new detector
func NewEmergencyCredentialStaleDetector() *EmergencyCredentialStaleDetector {
	return &EmergencyCredentialStaleDetector{
		BaseDetector: audit.NewBaseDetector("PA_EMERGENCY_CREDENTIAL_STALE", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *EmergencyCredentialStaleDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This is a tenant-level advisory check
	// Credential age cannot be verified from current data
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Emergency Account Credentials May Be Stale",
		Description: "Emergency access account credentials should be tested and rotated regularly. Establish a process to test break-glass accounts quarterly and rotate credentials every 90-180 days to ensure they work when needed.",
		Count:       1,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewEmergencyCredentialStaleDetector())
}
