package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC10Detector detects ESC10: Weak Certificate Mapping
type ESC10Detector struct {
	audit.BaseDetector
}

// NewESC10Detector creates a new detector
func NewESC10Detector() *ESC10Detector {
	return &ESC10Detector{
		BaseDetector: audit.NewBaseDetector("ESC10_WEAK_CERTIFICATE_MAPPING", audit.CategoryADCS),
	}
}

// Detect executes the detection
func (d *ESC10Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Certificate mapping strength is controlled by:
	// StrongCertificateBindingEnforcement registry key (HKLM\SYSTEM\CurrentControlSet\Services\Kdc)
	// 0 = Disabled, 1 = Compatibility mode (default), 2 = Full enforcement
	// Cannot be detected via LDAP - requires registry access

	count := 0
	if data.DomainInfo != nil {
		count = 1 // Flag as needing review if domain exists
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ESC10 - Certificate Mapping Configuration Review Required",
		Description: "Domain controllers should be configured for strong certificate mapping to prevent certificate impersonation attacks. This setting cannot be detected via LDAP.",
		Count:       count,
		Details: map[string]interface{}{
			"note":           "Check StrongCertificateBindingEnforcement registry key on DCs. Value should be 2 (Full Enforcement).",
			"registryPath":   "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\\StrongCertificateBindingEnforcement",
			"recommendation": "Set StrongCertificateBindingEnforcement to 2 for full enforcement. Test in compatibility mode (1) first.",
			"microsoftDoc":   "https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC10Detector())
}
