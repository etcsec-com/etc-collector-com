package privileged

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// backupOperatorsSID is the well-known SID for the built-in Backup
// Operators group (S-1-5-32-551), identical in every forest regardless of
// localization (e.g. "Opérateurs de sauvegarde" in fr-FR) or of a same-named
// decoy group placed elsewhere in the directory - see FindGroupBySID.
const backupOperatorsSID = "S-1-5-32-551"

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
	group := FindGroupBySID(data, backupOperatorsSID)

	var members []ClassifiedMember
	if group != nil {
		for _, m := range ResolveRealMembers(data, group) {
			// A disabled user or computer cannot authenticate ([MS-KILE]
			// "Check Account Policy for Every TGT Request" -
			// KDC_ERR_CLIENT_REVOKED), so it cannot exercise the privilege
			// while disabled - reported separately, at Low, by
			// BackupOperatorsOnDisabledAccountDetector. Nested groups, FSPs
			// and unknown members have no such state and stay here.
			if (m.Kind == MemberKindUser || m.Kind == MemberKindComputer) && m.Disabled {
				continue
			}
			members = append(members, m)
		}
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
		Description: "Active (non-disabled) real members of the Backup Operators group: users, nested groups, computers, and foreign security principals. Members can back up and restore all files on domain controllers regardless of the permissions protecting them, sign in interactively, log on as a batch job, and shut down the domain controller. Because they can replace any file - including OS files - on a domain controller, they are treated as service administrators with effective control comparable to Domain Admins, even though they cannot directly change server configuration or modify the membership of other administrative groups. A broad foreign security principal (e.g. Authenticated Users, Everyone) means the privilege is effectively unrestricted. Disabled user and computer members are reported separately by BACKUP_OPERATORS_MEMBER_ON_DISABLED_ACCOUNT.",
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
