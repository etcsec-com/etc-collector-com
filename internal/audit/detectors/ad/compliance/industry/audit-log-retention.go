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

	// This is a standing reminder, not a detection - no signal is
	// ever read from data, Count is fixed at 1, and it fired on every audit
	// regardless of domain state. That's honestly disclosed by "Review
	// Required" in the title, but SeverityMedium overstated it: a check
	// that can never distinguish a compliant domain from a non-compliant one
	// shouldn't carry the same alarm weight as an actual detected violation.
	// Lowered to Info, matching DATA_CLASSIFICATION_MISSING's already-honest
	// pattern for the same kind of "cannot verify via LDAP" reminder.
	// mappings.go (out of scope) already tags this detector with
	// NIST AU-4 (Audit Storage Capacity) and ANSSI Guide d'hygiène M36
	// ("logs activated") in addition to HDS 5.4 - referenced below for
	// context, without claiming this check verifies them (it doesn't).
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Audit Log Retention Review Required",
		Description: "Audit log retention settings cannot be verified via LDAP (event log size/retention lives on each DC, not in the directory). This is a standing reminder to verify manually, not an automated detection - it does not indicate an actual finding either way. Ensure logs are retained for compliance requirements (typically 90-365 days depending on regulation). Related (not verified by this check): NIST AU-4 (Audit Storage Capacity), ANSSI Guide d'hygiène M36 (logs activated).",
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
