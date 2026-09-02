package advanced

import (
	"context"
	"regexp"
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

var replicationGroups = []string{
	"Domain Controllers",
	"Enterprise Domain Controllers",
	"Administrators",
	"Domain Admins",
	"Enterprise Admins",
}

var serviceLikePattern = regexp.MustCompile(`(?i)^(svc|service|sync|repl)`)

// Detect executes the detection
func (d *ReplicaDirectoryChangesDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if u.Disabled || len(u.MemberOf) == 0 {
			continue
		}

		// Check for replication hints in description
		descLower := strings.ToLower(u.Description)
		hasReplicationHint := strings.Contains(descLower, "replication") ||
			strings.Contains(descLower, "dcsync") ||
			strings.Contains(descLower, "directory sync")

		// Check for service-like accounts with admin count
		isServiceLike := serviceLikePattern.MatchString(u.SAMAccountName)
		hasAdminCount := u.AdminCount
		isInReplicationGroup := helpers.IsInAnyGroup(u.MemberOf, replicationGroups)

		if hasReplicationHint || (isServiceLike && hasAdminCount && !isInReplicationGroup) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Potential Directory Replication Rights",
		Description: "Accounts that may have directory replication rights (DCSync capability). These accounts can extract all password hashes from the domain.",
		Count:       len(affected),
	}

	if data.IncludeDetails {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Review ACLs on domain head for DS-Replication-Get-Changes rights. Only Domain Controllers should have this permission.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewReplicaDirectoryChangesDetector())
}
