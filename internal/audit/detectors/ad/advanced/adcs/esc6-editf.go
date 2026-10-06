package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC6EditfDetector detects ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2 flag
type ESC6EditfDetector struct {
	audit.BaseDetector
}

// NewESC6EditfDetector creates a new detector
func NewESC6EditfDetector() *ESC6EditfDetector {
	return &ESC6EditfDetector{
		BaseDetector: audit.NewBaseDetector("ESC6_EDITF_ATTRIBUTESUBJECTALTNAME2", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *ESC6EditfDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// EDITF_ATTRIBUTESUBJECTALTNAME2 (bit 0x00040000) is a CA policy-module registry flag at
	// HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA>\PolicyModules\
	// CertificateAuthority_MicrosoftDefault.Policy\EditFlags - it is not an LDAP attribute,
	// so a directory-only collector structurally cannot read it. Microsoft Learn, Defender
	// for Identity - "Edit vulnerable Certificate Authority setting (ESC6)"
	// (learn.microsoft.com/defender-for-identity/security-assessment-edit-vulnerable-ca-setting)
	// documents this same flag and notes its own assessment "is available only to customers
	// who installed a sensor on an AD CS server" - i.e. even Microsoft's product needs local
	// access to the CA, not just directory data, to determine the real value.
	//
	// This finding is therefore a product signal (a manual-verification pointer), not a
	// compliance/vulnerability determination - Count reflects "AD CS is deployed, go check
	// the CA(s)", not a detected weakness.
	count := 0
	if len(data.CertTemplates) > 0 {
		count = 1 // AD CS is in scope; surfaced as a manual-check reminder.
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 (Manual Verification Required)",
		Description: "Not an automated finding: this collector reads LDAP data only, and EDITF_ATTRIBUTESUBJECTALTNAME2 is a CA-local registry flag with no LDAP-readable counterpart. This entry is a reminder to check it manually on the CA server(s) - it does not confirm the flag is set.",
		Count:       count,
		Details: map[string]interface{}{
			"note":           "Check CA registry for EDITF_ATTRIBUTESUBJECTALTNAME2 flag (0x00040000) - run: certutil -config - -getreg policy\\EditFlags",
			"recommendation": "Run: certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC6EditfDetector())
}
