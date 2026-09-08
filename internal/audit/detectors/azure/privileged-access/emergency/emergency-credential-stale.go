package emergency

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// EmergencyCredentialStaleDetector is a standing advisory for emergency
// account credential hygiene. Microsoft's current guidance (Microsoft Learn,
// "Manage emergency access admin accounts", learn.microsoft.com/en-us/entra/
// identity/role-based-access-control/security-emergency-access, "Security
// guardrails summary" and "Validate accounts regularly") no longer frames
// this as password rotation: it recommends phishing-resistant, non-expiring
// credentials (passkey/FIDO2 or certificate-based authentication) and
// validating that the accounts still work at least every 90 days. Whether a
// given tenant's emergency accounts meet this isn't something the collector
// can verify - authentication-method age isn't collected - so this stays an
// unconditional advisory rather than a per-tenant measurement.
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
	// This is a tenant-level advisory check: whether emergency access
	// account credentials meet Microsoft's current guidance cannot be
	// verified from collected data.
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Emergency Account Credential Hygiene Cannot Be Verified",
		Description: "Emergency access account credentials could not be verified against Microsoft's current guidance. Use phishing-resistant, non-expiring credentials (passkey/FIDO2 or certificate-based authentication) for break-glass accounts rather than passwords, and validate at least every 90 days that the accounts still work.",
		Count:       1,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewEmergencyCredentialStaleDetector())
}
