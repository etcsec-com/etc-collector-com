package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	adcsutils "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/adcs"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC1VulnerableTemplateDetector detects ESC1 vulnerable certificate templates
type ESC1VulnerableTemplateDetector struct {
	audit.BaseDetector
}

// NewESC1VulnerableTemplateDetector creates a new detector
func NewESC1VulnerableTemplateDetector() *ESC1VulnerableTemplateDetector {
	return &ESC1VulnerableTemplateDetector{
		BaseDetector: audit.NewBaseDetector("ESC1_VULNERABLE_TEMPLATE", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *ESC1VulnerableTemplateDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedNames []string

	for _, t := range data.CertTemplates {
		// Vulnerable if: client auth EKU AND enrollee can supply subject
		hasClientAuth := adcsutils.ContainsEKU(t.ExtendedKeyUsage, adcsutils.EKUClientAuth)
		enrolleeSuppliesSubject := (t.CertificateNameFlag & 0x1) != 0

		if hasClientAuth && enrolleeSuppliesSubject {
			name := t.Name
			if name == "" {
				name = t.DisplayName
			}
			affectedNames = append(affectedNames, name)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ESC1 Vulnerable Template",
		Description: "ADCS template with client auth + enrollee supplies subject. Enables domain compromise by obtaining cert for any user.",
		Count:       len(affectedNames),
	}

	if data.IncludeDetails && len(affectedNames) > 0 {
		entities := make([]types.AffectedEntity, len(affectedNames))
		for i, name := range affectedNames {
			entities[i] = types.AffectedEntity{
				Type:           "certTemplate",
				SAMAccountName: name,
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

// init() commented out - duplicate of adcs/esc1.go
// func init() {
// 	audit.MustRegister(NewESC1VulnerableTemplateDetector())
// }
