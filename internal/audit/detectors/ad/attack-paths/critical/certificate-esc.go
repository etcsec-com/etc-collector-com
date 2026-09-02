package critical

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	adcsutils "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/adcs"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CertificateEscDetector detects ADCS certificate template paths to Domain Admin
type CertificateEscDetector struct {
	audit.BaseDetector
}

// NewCertificateEscDetector creates a new detector
func NewCertificateEscDetector() *CertificateEscDetector {
	return &CertificateEscDetector{
		BaseDetector: audit.NewBaseDetector("PATH_CERTIFICATE_ESC", audit.CategoryAttackPaths),
	}
}

// Detect executes the detection
func (d *CertificateEscDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var vulnerableTemplates []string

	for _, t := range data.CertTemplates {
		// ESC1-like: client auth + enrollee supplies subject
		hasClientAuth := adcsutils.ContainsEKU(t.ExtendedKeyUsage, adcsutils.EKUClientAuth)
		enrolleeSupplies := (t.CertificateNameFlag & 0x1) != 0

		if hasClientAuth && enrolleeSupplies {
			name := t.Name
			if name == "" {
				name = t.DisplayName
			}
			vulnerableTemplates = append(vulnerableTemplates, name)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Certificate Template Escalation to Domain Admin",
		Description: "Vulnerable certificate templates (ESC1-like) allow users to request certificates for any user including Domain Admins.",
		Count:       len(vulnerableTemplates),
	}

	if data.IncludeDetails && len(vulnerableTemplates) > 0 {
		entities := make([]types.AffectedEntity, len(vulnerableTemplates))
		for i, name := range vulnerableTemplates {
			entities[i] = types.AffectedEntity{
				Type:           "certTemplate",
				SAMAccountName: name,
			}
		}
		finding.AffectedEntities = entities
		finding.Details = map[string]interface{}{
			"vulnerableTemplates": vulnerableTemplates,
			"attackVector":        "Enroll in vulnerable template → Request cert as DA → Authenticate as DA",
			"mitigation":          "Disable ENROLLEE_SUPPLIES_SUBJECT flag, restrict enrollment permissions, use Certificate Manager Approval",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCertificateEscDetector())
}
