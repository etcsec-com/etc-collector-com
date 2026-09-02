package industry

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// BackupNotVerifiedDetector checks for backup verification compliance
type BackupNotVerifiedDetector struct {
	audit.BaseDetector
}

// NewBackupNotVerifiedDetector creates a new detector
func NewBackupNotVerifiedDetector() *BackupNotVerifiedDetector {
	return &BackupNotVerifiedDetector{
		BaseDetector: audit.NewBaseDetector("BACKUP_AD_NOT_VERIFIED", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *BackupNotVerifiedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Backup verification status cannot be determined via LDAP
	// This is a reminder finding for manual verification

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "AD Backup Verification Required",
		Description: "Active Directory backup verification status cannot be determined via LDAP. Ensure regular AD backups are performed and periodically tested.",
		Count:       0,
		Details: map[string]interface{}{
			"category": "Industry Best Practices",
			"recommendations": []string{
				"Perform system state backups of all DCs at least daily",
				"Test restore procedures quarterly",
				"Maintain offline/air-gapped backup copies",
				"Document and test AD forest recovery procedures",
				"Verify SYSVOL and NTDS.dit are included in backups",
			},
			"note": "Manual verification required - check backup solution and restore test logs",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewBackupNotVerifiedDetector())
}
