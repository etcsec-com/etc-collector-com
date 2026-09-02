package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC6Detector detects ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 Flag
type ESC6Detector struct {
	audit.BaseDetector
}

// NewESC6Detector creates a new detector
func NewESC6Detector() *ESC6Detector {
	return &ESC6Detector{
		BaseDetector: audit.NewBaseDetector("ESC6_EDITF_FLAG", audit.CategoryADCS),
	}
}

// Detect executes the detection
func (d *ESC6Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// EDITF_ATTRIBUTESUBJECTALTNAME2 (0x00040000) is stored in registry at:
	// HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA Name>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags
	// Cannot be detected via LDAP alone

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ESC6 - CA Configuration Review Required",
		Description: "Certificate Authorities should be checked for EDITF_ATTRIBUTESUBJECTALTNAME2 flag which allows any certificate requestor to specify a SAN.",
		Count:       0, // Cannot detect via LDAP
		Details: map[string]interface{}{
			"note":       "Check registry key EditFlags on CA servers. Flag 0x00040000 indicates vulnerability.",
			"casToCheck": len(data.CertTemplates) > 0, // Proxy for CA existence
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC6Detector())
}
