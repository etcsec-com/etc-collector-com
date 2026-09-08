package privileged

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
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
	// reads the group's own real membership (Members/Member LDAP
	// attribute) instead of scanning data.Users[].MemberOf, which only ever
	// shows direct user members and stayed silent when Backup Operators'
	// only member was a foreignSecurityPrincipal (e.g. S-1-1-0 Everyone,
	// seen on the lab DC).
	group := FindBuiltinGroup(data.Groups, "Backup Operators")

	var members []ClassifiedMember
	if group != nil {
		members = ResolveRealMembers(data, group)
	}

	entities := make([]types.AffectedEntity, len(members))
	for i, m := range members {
		entities[i] = m.Entity
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Backup Operators Member",
		Description: "Real members of the Backup Operators group (users, nested groups, computers, foreign security principals). Can backup/restore files and bypass ACLs. A broad foreign security principal (e.g. Authenticated Users, Everyone) means the privilege is effectively unrestricted.",
		Count:       len(members),
	}

	if data.IncludeDetails && len(entities) > 0 {
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewBackupOperatorsDetector())
}
