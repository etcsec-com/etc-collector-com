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
	// Certificate mapping strength is controlled by StrongCertificateBindingEnforcement,
	// a DWORD under HKLM\SYSTEM\CurrentControlSet\Services\Kdc on each domain controller
	// (0 = Disabled, 1 = Compatibility mode, 2 = Full Enforcement). Per Microsoft Support
	// KB5014754 ("Certificate-based authentication changes on Windows domain controllers"
	// - "How Windows domain controllers determine certificate mapping" / enforcement
	// timeline section), this is a DC-local registry value: it has no LDAP-readable
	// counterpart, so a directory-only collector structurally cannot observe it. KB5014754
	// also states that as of the September 2025 update, Full Enforcement is mandatory and
	// the key no longer permits reverting to Compatibility/Disabled - so on a DC that is
	// still receiving security updates, weak certificate mapping should already be gone
	// regardless of this finding.
	//
	// Because the actual enforcement state can't be measured here, this finding is a
	// product signal (a manual-verification pointer), not a compliance/vulnerability
	// determination - Count reflects "AD CS is deployed, go check the DCs", not a
	// detected weakness.
	count := 0
	if data.DomainInfo != nil {
		count = 1 // AD CS is in scope for this domain; surfaced as a manual-check reminder.
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "ESC10 - Certificate Mapping Enforcement (Manual Verification Required)",
		Description: "Not an automated finding: whether domain controllers reject weak certificate mappings depends on the StrongCertificateBindingEnforcement registry value on each DC, which is local to the DC and cannot be read via LDAP. This entry is a reminder to verify that setting manually - it does not confirm a vulnerability.",
		Count:       count,
		Details: map[string]interface{}{
			"note":           "Check StrongCertificateBindingEnforcement registry key on DCs. Value should be 2 (Full Enforcement). Since the September 2025 update this is mandatory and no longer configurable.",
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
