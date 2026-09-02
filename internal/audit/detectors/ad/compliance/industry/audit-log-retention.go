package industry

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AuditLogRetentionDetector checks for audit log retention compliance
type AuditLogRetentionDetector struct {
	audit.BaseDetector
}

// NewAuditLogRetentionDetector creates a new detector
func NewAuditLogRetentionDetector() *AuditLogRetentionDetector {
	return &AuditLogRetentionDetector{
		BaseDetector: audit.NewBaseDetector("AUDIT_LOG_RETENTION_SHORT", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *AuditLogRetentionDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Audit log retention cannot be fully verified via LDAP
	// This requires access to event log settings on domain controllers

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Audit Log Retention Review Required",
		Description: "Audit log retention settings cannot be verified via LDAP. Ensure logs are retained for compliance requirements (typically 90-365 days depending on regulation).",
		Count:       1,
		Details: map[string]interface{}{
			"category": "Industry Best Practices",
			"recommendations": map[string]interface{}{
				"PCI-DSS": "90 days minimum, 1 year for compliance",
				"HIPAA":   "6 years retention",
				"SOX":     "7 years retention",
				"GDPR":    "As long as necessary for processing",
				"General": "Minimum 90 days active, 1 year archive",
			},
			"note": "Verify event log maximum size and retention settings on all DCs",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAuditLogRetentionDetector())
}
