package industry

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DataClassificationDetector checks for data classification compliance
type DataClassificationDetector struct {
	audit.BaseDetector
}

// NewDataClassificationDetector creates a new detector
func NewDataClassificationDetector() *DataClassificationDetector {
	return &DataClassificationDetector{
		BaseDetector: audit.NewBaseDetector("DATA_CLASSIFICATION_MISSING", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *DataClassificationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Data classification compliance cannot be fully verified via LDAP.
	// This is an informational finding for review.
	//
	// Source-check outcome, no behavior change: unlike
	// AUDIT_LOG_RETENTION_SHORT, this detector already used SeverityInfo and
	// an honest "Review Required" title with no numbered-standard claim
	// (framework/HDS/RGPD tags in mappings.go are generic, non-normative
	// cross-references, not a claim this check verifies them) - by design,
	// Count is fixed at 1 as a standing reminder, not a detection.

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Data Classification Review Required",
		Description: "Data classification implementation cannot be verified via LDAP. Ensure sensitive AD attributes and objects are properly classified.",
		Count:       1,
		Details: map[string]interface{}{
			"category": "Industry Best Practices",
			"sensitivADData": []string{
				"Password hashes (NTDS.dit)",
				"Service account credentials",
				"LAPS passwords",
				"BitLocker recovery keys",
				"Certificate private keys",
				"Confidential attributes",
			},
			"recommendations": []string{
				"Implement confidentiality flags on sensitive attributes",
				"Use AD Rights Management for document protection",
				"Enable confidential attribute protection",
				"Audit access to sensitive AD data",
			},
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDataClassificationDetector())
}
