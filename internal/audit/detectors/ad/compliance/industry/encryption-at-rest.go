package industry

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// EncryptionAtRestDetector checks for encryption at rest compliance
type EncryptionAtRestDetector struct {
	audit.BaseDetector
}

// NewEncryptionAtRestDetector creates a new detector
func NewEncryptionAtRestDetector() *EncryptionAtRestDetector {
	return &EncryptionAtRestDetector{
		BaseDetector: audit.NewBaseDetector("ENCRYPTION_AT_REST_DISABLED", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *EncryptionAtRestDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Encryption at rest status cannot be verified via LDAP
	// This requires BitLocker/storage encryption verification
	//
	// Count was hardcoded to 1 regardless of any domain data (no
	// signal is ever read), and the ID/type name asserts "DISABLED" as a
	// measured fact. SeverityMedium overstated a check that can never tell a
	// compliant domain from a non-compliant one apart - same defect already
	// fixed for AUDIT_LOG_RETENTION_SHORT (industry/audit-log-retention.go)
	// and already avoided by DATA_CLASSIFICATION_MISSING. Lowered to Info to
	// match that precedent: this stays a standing "verify manually" reminder,
	// not a detection, so it shouldn't carry a confirmed-violation's weight
	// in every report. Title/Description already avoid claiming a measured
	// violation ("Review Required" / "cannot be verified") - only Severity
	// needed correcting.

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Encryption at Rest Review Required",
		Description: "Encryption at rest status for AD data cannot be verified via LDAP. Ensure domain controllers use disk encryption.",
		Count:       1,
		Details: map[string]interface{}{
			"category": "Industry Best Practices",
			"criticalData": []string{
				"NTDS.dit (AD database)",
				"SYSVOL (Group Policy data)",
				"AD backup files",
				"Certificate Services database",
			},
			"recommendations": []string{
				"Enable BitLocker on all domain controller volumes",
				"Store BitLocker recovery keys securely (not only in AD)",
				"Encrypt AD backup storage",
				"Use encrypted communications for DC replication over WAN",
			},
			"note": "Manual verification required - check BitLocker status on all DCs",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewEncryptionAtRestDetector())
}
