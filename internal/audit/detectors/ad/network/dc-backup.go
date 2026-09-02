package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DcBackupDetector checks for outdated AD backups
type DcBackupDetector struct {
	audit.BaseDetector
}

// NewDcBackupDetector creates a new detector
func NewDcBackupDetector() *DcBackupDetector {
	return &DcBackupDetector{
		BaseDetector: audit.NewBaseDetector("DC_BACKUP_OLD", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *DcBackupDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Domain Controller Backup Review",
		Description: "Active Directory should be backed up regularly. Tombstone lifetime is 180 days.",
	}

	if data.DomainInfo == nil || data.DomainInfo.LastADBackupDate == nil {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"lastBackup":     "unknown",
			"recommendation": "Verify Windows Server Backup is configured on all DCs.",
		}
		return []types.Finding{finding}
	}

	daysSinceBackup := int(data.Now.Sub(*data.DomainInfo.LastADBackupDate).Hours() / 24)
	if daysSinceBackup > 60 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"lastBackup":      data.DomainInfo.LastADBackupDate.Format("2006-01-02"),
			"daysSinceBackup": daysSinceBackup,
			"recommendation":  "Back up Active Directory at least monthly. Tombstone lifetime is 180 days.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDcBackupDetector())
}
