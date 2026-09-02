package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SchemaSDChangesDetector detects recent modifications to the Schema security descriptor
type SchemaSDChangesDetector struct {
	audit.BaseDetector
}

// NewSchemaSDChangesDetector creates a new detector
func NewSchemaSDChangesDetector() *SchemaSDChangesDetector {
	return &SchemaSDChangesDetector{
		BaseDetector: audit.NewBaseDetector("SCHEMA_SD_RECENT_CHANGE", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *SchemaSDChangesDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := 0

	if !data.SchemaSDLastChanged.IsZero() {
		cutoff := data.Now.AddDate(0, 0, -90)
		if data.SchemaSDLastChanged.After(cutoff) {
			count = 1
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Schema Security Descriptor Recently Modified",
		Description: "The security descriptor on the Active Directory Schema naming context has been modified within the last 90 days. Schema permission changes are rare in production and may indicate privilege escalation or unauthorized access.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSchemaSDChangesDetector())
}
