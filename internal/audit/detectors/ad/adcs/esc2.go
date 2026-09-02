package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC2Detector detects ESC2: Any Purpose Certificate Template
type ESC2Detector struct {
	audit.BaseDetector
}

// NewESC2Detector creates a new detector
func NewESC2Detector() *ESC2Detector {
	return &ESC2Detector{
		BaseDetector: audit.NewBaseDetector("ESC2_ANY_PURPOSE", audit.CategoryADCS),
	}
}

// Detect executes the detection
func (d *ESC2Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedTemplates []types.CertTemplate

	for _, t := range data.CertTemplates {
		ekus := t.ExtendedKeyUsage

		// Has "Any Purpose" EKU
		hasAnyPurpose := ContainsEKU(ekus, EKUAnyPurpose)

		// No EKU constraint (implies any purpose)
		noEkuConstraint := len(ekus) == 0

		// Doesn't require manager approval
		noApprovalRequired := (t.EnrollmentFlag & CTFlagPendAllRequests) == 0

		if (hasAnyPurpose || noEkuConstraint) && noApprovalRequired {
			affectedTemplates = append(affectedTemplates, t)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ESC2 - Any Purpose Certificate Template",
		Description: "Certificate template has 'Any Purpose' EKU or no EKU constraints, allowing issued certificates to be used for any purpose including client authentication.",
		Count:       len(affectedTemplates),
	}

	if data.IncludeDetails && len(affectedTemplates) > 0 {
		finding.AffectedEntities = helpers.ToAffectedCertTemplateEntities(affectedTemplates)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC2Detector())
}
