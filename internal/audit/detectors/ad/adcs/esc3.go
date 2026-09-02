package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC3Detector detects ESC3: Enrollment Agent Certificate Template
type ESC3Detector struct {
	audit.BaseDetector
}

// NewESC3Detector creates a new detector
func NewESC3Detector() *ESC3Detector {
	return &ESC3Detector{
		BaseDetector: audit.NewBaseDetector("ESC3_ENROLLMENT_AGENT", audit.CategoryADCS),
	}
}

// Detect executes the detection
func (d *ESC3Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedTemplates []types.CertTemplate

	for _, t := range data.CertTemplates {
		ekus := t.ExtendedKeyUsage

		// Has Certificate Request Agent EKU
		hasEnrollmentAgent := ContainsEKU(ekus, EKUCertificateRequestAgent)

		// Doesn't require manager approval
		noApprovalRequired := (t.EnrollmentFlag & CTFlagPendAllRequests) == 0

		if hasEnrollmentAgent && noApprovalRequired {
			affectedTemplates = append(affectedTemplates, t)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ESC3 - Enrollment Agent Certificate Template",
		Description: "Certificate template allows issuance of enrollment agent certificates, which can be used to enroll certificates on behalf of other users.",
		Count:       len(affectedTemplates),
	}

	if data.IncludeDetails && len(affectedTemplates) > 0 {
		finding.AffectedEntities = helpers.ToAffectedCertTemplateEntities(affectedTemplates)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC3Detector())
}
