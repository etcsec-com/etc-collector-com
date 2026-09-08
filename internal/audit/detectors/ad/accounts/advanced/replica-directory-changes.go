package advanced

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ReplicaDirectoryChangesDetector detects accounts with directory replication rights
type ReplicaDirectoryChangesDetector struct {
	audit.BaseDetector
}

// NewReplicaDirectoryChangesDetector creates a new detector
func NewReplicaDirectoryChangesDetector() *ReplicaDirectoryChangesDetector {
	return &ReplicaDirectoryChangesDetector{
		BaseDetector: audit.NewBaseDetector("REPLICA_DIRECTORY_CHANGES", audit.CategoryAccounts),
	}
}

// Detect executes the detection.
//
// DCSync capability requires holding both the DS-Replication-Get-Changes
// (types.GUIDDSReplicationGetChanges, 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
// and DS-Replication-Get-Changes-All
// (types.GUIDDSReplicationGetChangesAll, 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
// extended rights on the domain root object (Microsoft Learn, Win32 AD
// Schema reference, "DS-Replication-Get-Changes[-All] extended right").
// The previous version of this detector never read an ACL: it guessed by
// keyword in Description ("replication"/"dcsync"/"directory sync") or by a
// svc/service/sync/repl name prefix plus adminCount - neither necessary
// nor sufficient for actually holding the right, while a genuine holder
// with none of those naming habits was invisible. The ACL data is already
// collected (data.ACLEntries); read it directly on the domain root, the
// same way LAPS_PASSWORD_READABLE recomputes its CONTROL_ACCESS grant
// instead of trusting a derived flag.
func (d *ReplicaDirectoryChangesDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var domainDN string
	if data.DomainInfo != nil {
		domainDN = strings.ToLower(data.DomainInfo.DomainDN)
		if domainDN == "" {
			domainDN = strings.ToLower(data.DomainInfo.DN)
		}
	}

	userBySID := make(map[string]int, len(data.Users))
	for i := range data.Users {
		if data.Users[i].ObjectSID != "" {
			userBySID[data.Users[i].ObjectSID] = i
		}
	}

	holders := make(map[int]bool)
	if domainDN != "" {
		for _, ace := range data.ACLEntries {
			if strings.ToLower(ace.ObjectDN) != domainDN {
				continue
			}
			if !audit.IsGrantACE(ace.AceType) {
				continue
			}
			if ace.AccessMask&types.MaskControlAccess == 0 {
				continue
			}
			ot := strings.ToLower(ace.ObjectType)
			if ot != strings.ToLower(types.GUIDDSReplicationGetChanges) &&
				ot != strings.ToLower(types.GUIDDSReplicationGetChangesAll) {
				continue
			}
			if audit.IsBuiltinAdminTrustee(ace.Trustee) {
				continue // Domain Controllers / Domain Admins / Enterprise Admins hold this by default
			}
			if idx, ok := userBySID[ace.Trustee]; ok {
				holders[idx] = true
			}
		}
	}

	var affected []types.User
	for idx := range holders {
		affected = append(affected, data.Users[idx])
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Directory Replication Rights (DCSync)",
		Description: "Non-administrative accounts hold the DS-Replication-Get-Changes and DS-Replication-Get-Changes-All extended rights on the domain root. These accounts can extract all password hashes from the domain (DCSync).",
		Count:       len(affected),
	}

	if data.IncludeDetails {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		if len(affected) > 0 {
			finding.Details = map[string]interface{}{
				"recommendation": "Review ACLs on the domain head for DS-Replication-Get-Changes[-All] rights. Only Domain Controllers and tier-0 administrators should have this permission.",
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewReplicaDirectoryChangesDetector())
}
