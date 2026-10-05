package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC8HttpEnrollmentDetector detects ESC8 HTTP enrollment
type ESC8HttpEnrollmentDetector struct {
	audit.BaseDetector
}

// NewESC8HttpEnrollmentDetector creates a new detector
func NewESC8HttpEnrollmentDetector() *ESC8HttpEnrollmentDetector {
	return &ESC8HttpEnrollmentDetector{
		BaseDetector: audit.NewBaseDetector("ESC8_HTTP_ENROLLMENT", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *ESC8HttpEnrollmentDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// HTTP enrollment endpoints typically at http://<CA>/certsrv/
	// Cannot be fully detected via LDAP - requires network connectivity check

	count := 0
	if len(data.CertTemplates) > 0 {
		count = 1 // Flag as needing review if CAs exist
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "ESC8 HTTP Enrollment",
		Description: "ADCS web enrollment via HTTP. Enables NTLM relay attacks against certificate enrollment.",
		Count:       count,
		Details: map[string]interface{}{
			"note":           "Check for http://<CA>/certsrv/ endpoints",
			"recommendation": "Disable HTTP enrollment or require HTTPS with Extended Protection for Authentication",
		},
	}

	return []types.Finding{finding}
}

// init() commented out - duplicate of adcs/esc8.go
// func init() {
// 	audit.MustRegister(NewESC8HttpEnrollmentDetector())
// }
