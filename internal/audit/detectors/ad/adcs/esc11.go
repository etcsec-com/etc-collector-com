package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC11Detector detects ESC11: IF_ENFORCEENCRYPTICERTREQUEST Not Enforced
type ESC11Detector struct {
	audit.BaseDetector
}

// NewESC11Detector creates a new detector
func NewESC11Detector() *ESC11Detector {
	return &ESC11Detector{
		BaseDetector: audit.NewBaseDetector("ESC11_ICERT_REQUEST_ENFORCEMENT", audit.CategoryADCS),
	}
}

// Detect executes the detection
func (d *ESC11Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// IF_ENFORCEENCRYPTICERTREQUEST is stored in registry at:
	// HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA>\InterfaceFlags
	// Flag 0x00000200 should be set to enforce RPC encryption
	// Cannot be detected via LDAP alone

	count := 0
	if len(data.CertTemplates) > 0 {
		count = 1 // Flag as needing review if CAs exist
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "ESC11 - RPC Encryption Enforcement Check Required",
		Description: "Certificate Authorities should enforce RPC encryption (IF_ENFORCEENCRYPTICERTREQUEST flag) to prevent NTLM relay attacks to the ICertPassage RPC interface.",
		Count:       count,
		Details: map[string]interface{}{
			"note":           "Check InterfaceFlags registry key on CA servers. Flag 0x00000200 (IF_ENFORCEENCRYPTICERTREQUEST) should be set.",
			"registryPath":   "HKLM\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\<CA>\\InterfaceFlags",
			"recommendation": "Set IF_ENFORCEENCRYPTICERTREQUEST flag using: certutil -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC11Detector())
}
