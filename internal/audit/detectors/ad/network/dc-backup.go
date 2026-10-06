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
		Description: "Active Directory should be backed up regularly (tombstone lifetime is 180 days). This check has no direct visibility into backup jobs: no attribute in the directory records when a backup last completed. It uses the most recent whenChanged timestamp across NTDS Settings objects (CN=Sites) as an indirect activity indicator, since a valid AD backup updates replication metadata. That same timestamp also moves for unrelated reasons (site/topology edits, FSMO transfers, DC promotion or demotion), so it can look more recent than the last real backup. Treat this as a prompt to verify backups directly, not as a backup date.",
	}

	if data.DomainInfo == nil || data.DomainInfo.LastADBackupDate == nil {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"ntdsMetadataActivity": "unknown",
			"recommendation":       "Verify Windows Server Backup (or your backup solution) is configured on all DCs.",
		}
		return []types.Finding{finding}
	}

	daysSinceActivity := int(data.Now.Sub(*data.DomainInfo.LastADBackupDate).Hours() / 24)
	if daysSinceActivity > 60 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"lastNtdsMetadataChange": data.DomainInfo.LastADBackupDate.Format("2006-01-02"),
			"daysSinceChange":        daysSinceActivity,
			"recommendation":         "This is an indirect indicator, not a backup timestamp - verify actual backup jobs (e.g. wbadmin get versions) rather than relying on this check alone. Back up Active Directory at least monthly; tombstone lifetime is 180 days.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDcBackupDetector())
}
