package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// BackupOperatorsDetector detects Backup Operators membership
type BackupOperatorsDetector struct {
	audit.BaseDetector
}

// NewBackupOperatorsDetector creates a new detector
func NewBackupOperatorsDetector() *BackupOperatorsDetector {
	return &BackupOperatorsDetector{
		BaseDetector: audit.NewBaseDetector("BACKUP_OPERATORS_MEMBER", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *BackupOperatorsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if len(u.MemberOf) == 0 {
			continue
		}
		for _, dn := range u.MemberOf {
			if strings.Contains(dn, "CN=Backup Operators") {
				affected = append(affected, u)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Backup Operators Member",
		Description: "Users in Backup Operators group. Can backup/restore files and bypass ACLs.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewBackupOperatorsDetector())
}
