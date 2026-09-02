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

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
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
