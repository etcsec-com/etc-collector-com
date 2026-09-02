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
	// This detection requires checking CA registry flags
	// Flag EDITF_ATTRIBUTESUBJECTALTNAME2 (0x40000) allows arbitrary SAN
	// Cannot be fully detected via LDAP alone

	count := 0
	if len(data.CertTemplates) > 0 {
		count = 1 // Flag as needing review if CAs exist
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ESC6 EDITF Flag",
		Description: "ADCS CA with EDITF_ATTRIBUTESUBJECTALTNAME2 flag. Allows specifying arbitrary SAN in certificate requests.",
		Count:       count,
		Details: map[string]interface{}{
			"note":           "Check CA registry for EDITF_ATTRIBUTESUBJECTALTNAME2 flag (0x40000)",
			"recommendation": "Run: certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC6EditfDetector())
}
