package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC9Detector detects ESC9: No Security Extension
type ESC9Detector struct {
	audit.BaseDetector
}

// NewESC9Detector creates a new detector
func NewESC9Detector() *ESC9Detector {
	return &ESC9Detector{
		BaseDetector: audit.NewBaseDetector("ESC9_NO_SECURITY_EXTENSION", audit.CategoryADCS),
	}
}

// Detect executes the detection
func (d *ESC9Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedTemplates []types.CertTemplate

	for _, t := range data.CertTemplates {
		// A template omits the SID security extension when the
		// CT_FLAG_NO_SECURITY_EXTENSION bit is set in msPKI-Enrollment-Flag.
		// Only templates that can also be used for authentication are
		// exploitable, so require an authentication EKU as well.
		noSecurityExtension := (t.EnrollmentFlag & CTFlagNoSecurityExtension) != 0
		if noSecurityExtension && HasAuthenticationEKU(t.ExtendedKeyUsage) {
			affectedTemplates = append(affectedTemplates, t)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ESC9 - No Security Extension in Certificate Template",
		Description: "Certificate templates with the CT_FLAG_NO_SECURITY_EXTENSION flag set in msPKI-Enrollment-Flag issue certificates without the szOID_NTDS_CA_SECURITY_EXT SID extension. Combined with weak certificate mapping, this allows certificate impersonation attacks.",
		Count:       len(affectedTemplates),
	}

	if data.IncludeDetails && len(affectedTemplates) > 0 {
		finding.AffectedEntities = helpers.ToAffectedCertTemplateEntities(affectedTemplates)
		finding.Details = map[string]interface{}{
			"recommendation":     "Clear the CT_FLAG_NO_SECURITY_EXTENSION flag on the template so issued certificates carry the SID security extension, and enable strong certificate mapping.",
			"vulnerabilityChain": "ESC9 + weak certificate mapping = impersonation",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC9Detector())
}
