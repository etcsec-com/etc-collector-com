package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC1Detector detects ESC1: Misconfigured Certificate Template
type ESC1Detector struct {
	audit.BaseDetector
}

// NewESC1Detector creates a new detector
func NewESC1Detector() *ESC1Detector {
	return &ESC1Detector{
		BaseDetector: audit.NewBaseDetector("ESC1_VULNERABLE_TEMPLATE", audit.CategoryADCS),
	}
}

// Detect executes the detection
func (d *ESC1Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedTemplates []types.CertTemplate

	for _, t := range data.CertTemplates {
		// Enrollee can supply subject
		enrolleeSuppliesSubject := (t.SubjectNameFlag & CTFlagEnrolleeSuppliesSubject) != 0

		// Has authentication capability
		canAuthenticate := HasAuthenticationEKU(t.ExtendedKeyUsage)

		// Doesn't require manager approval
		noApprovalRequired := (t.EnrollmentFlag & CTFlagPendAllRequests) == 0

		if enrolleeSuppliesSubject && canAuthenticate && noApprovalRequired {
			affectedTemplates = append(affectedTemplates, t)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "ESC1 - Misconfigured Certificate Template",
		Description: "Certificate template allows enrollee to specify Subject Alternative Name (SAN) and has client authentication EKU, enabling privilege escalation to any user/computer.",
		Count:       len(affectedTemplates),
	}

	if data.IncludeDetails && len(affectedTemplates) > 0 {
		finding.AffectedEntities = helpers.ToAffectedCertTemplateEntities(affectedTemplates)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC1Detector())
}
