package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	adcsutils "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/adcs"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC3EnrollmentAgentDetector detects ESC3 enrollment agent templates
type ESC3EnrollmentAgentDetector struct {
	audit.BaseDetector
}

// NewESC3EnrollmentAgentDetector creates a new detector
func NewESC3EnrollmentAgentDetector() *ESC3EnrollmentAgentDetector {
	return &ESC3EnrollmentAgentDetector{
		BaseDetector: audit.NewBaseDetector("ESC3_ENROLLMENT_AGENT", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *ESC3EnrollmentAgentDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedNames []string

	for _, t := range data.CertTemplates {
		// Vulnerable if: has Certificate Request Agent EKU
		if adcsutils.ContainsEKU(t.ExtendedKeyUsage, adcsutils.EKUCertRequestAgent) {
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
		Title:       "ESC3 Enrollment Agent",
		Description: "ADCS template with enrollment agent EKU. Can request certificates on behalf of other users.",
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

// init() commented out - duplicate of adcs/esc3.go
// func init() {
// 	audit.MustRegister(NewESC3EnrollmentAgentDetector())
// }
