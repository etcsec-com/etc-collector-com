package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	adcsutils "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/adcs"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC2AnyPurposeDetector detects ESC2 Any Purpose EKU
type ESC2AnyPurposeDetector struct {
	audit.BaseDetector
}

// NewESC2AnyPurposeDetector creates a new detector
func NewESC2AnyPurposeDetector() *ESC2AnyPurposeDetector {
	return &ESC2AnyPurposeDetector{
		BaseDetector: audit.NewBaseDetector("ESC2_ANY_PURPOSE", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *ESC2AnyPurposeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedNames []string

	for _, t := range data.CertTemplates {
		// Vulnerable if: Any Purpose EKU OR no usage restriction (empty EKU)
		hasAnyPurpose := adcsutils.ContainsEKU(t.ExtendedKeyUsage, adcsutils.EKUAnyPurpose)
		isEmpty := len(t.ExtendedKeyUsage) == 0

		if hasAnyPurpose || isEmpty {
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
		Title:       "ESC2 Any Purpose",
		Description: "ADCS template with Any Purpose EKU or no usage restriction. Certificate can be used for domain authentication.",
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

// init() commented out - duplicate of adcs/esc2.go
// func init() {
// 	audit.MustRegister(NewESC2AnyPurposeDetector())
// }
