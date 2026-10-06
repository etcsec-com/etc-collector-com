package advanced

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ReplicaDirectoryChangesOnDisabledAccountDetector checks the same
// population as ReplicaDirectoryChangesDetector - non-built-in-admin users
// holding BOTH DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
// (or an equivalent grant) on the domain root - restricted to DISABLED
// accounts. Split out for the same reason as admin-count-orphaned.go /
// admin-count-orphaned-on-disabled-account.go and the delegation and Backup
// Operators families (*_ON_DISABLED_ACCOUNT): a disabled account cannot
// obtain a ticket-granting ticket of its own ([MS-KILE], "Check Account
// Policy for Every TGT Request", KDC_ERR_CLIENT_REVOKED), so it cannot
// authenticate and cannot currently run DCSync - the residual ACE grant is
// dormant, not resolved, and returns to full relevance the instant the
// account is re-enabled. Reported at Low rather than Critical for that
// reason. The suffix names the population covered, not a mechanism that was
// turned off - _DISABLED alone is reserved elsewhere for "a protection was
// disabled".
type ReplicaDirectoryChangesOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewReplicaDirectoryChangesOnDisabledAccountDetector creates a new detector
func NewReplicaDirectoryChangesOnDisabledAccountDetector() *ReplicaDirectoryChangesOnDisabledAccountDetector {
	return &ReplicaDirectoryChangesOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("REPLICA_DIRECTORY_CHANGES_ON_DISABLED_ACCOUNT", audit.CategoryAccounts),
	}
}

// Detect executes the detection.
func (d *ReplicaDirectoryChangesOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	holders := replicaRootHolders(data)

	var affected []types.User
	for idx := range holders {
		if !data.Users[idx].Disabled {
			continue // active accounts are reported separately, at Critical, by ReplicaDirectoryChangesDetector
		}
		affected = append(affected, data.Users[idx])
	}
	sortUsersByDN(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Directory Replication Rights (DCSync) - Disabled Account",
		Description: "Disabled accounts hold both the DS-Replication-Get-Changes and DS-Replication-Get-Changes-All extended rights - or an equivalent grant (GenericAll, or a CONTROL_ACCESS ACE with no ObjectType, which AD grants as every extended right) - on the domain root (Microsoft Learn, Win32 AD Schema reference, \"DS-Replication-Get-Changes[-All] extended right\"). A disabled account cannot obtain a new ticket-granting ticket ([MS-KILE], \"Check Account Policy for Every TGT Request\", KDC_ERR_CLIENT_REVOKED); however [MS-KILE] does not revoke a ticket-granting ticket already issued before the account was disabled, and when POLICY_KERBEROS_VALIDATE_CLIENT is set, [MS-KILE] 3.3.5.7.1 (\"Check Account Policy for Every Session Ticket Request\") still has the account KDC re-check a ticket-granting ticket older than 20 minutes on every new service-ticket request and reject it once Disabled is true - so the residual window is bounded by the lifetime of service tickets already issued before that 20-minute re-check, not by the ticket-granting ticket's own lifetime. The grant itself is not removed by disabling the account, and it returns to full relevance the instant the account is re-enabled. Holding only one of the two rights cannot perform DCSync and is not reported. Limits: only user accounts are checked - computer accounts and groups holding the rights are not, and group membership is not expanded to the users inside; an ACE flagged inherit-only (applies only to descendants, not the domain root itself) is ignored; and an explicit ACCESS_DENIED ACE elsewhere in the same ACL is not evaluated against a separate grant.",
		Count:       len(affected),
	}

	if data.IncludeDetails {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		if len(affected) > 0 {
			finding.Details = map[string]interface{}{
				"recommendation": "Remove the DS-Replication-Get-Changes[-All] grant (or its GenericAll/CONTROL_ACCESS-without-ObjectType equivalent) from the domain root ACL. If the account is expected to stay disabled and unused, consider removing it instead of leaving a stale replication grant in place.",
				"impact":         "The account returns to full DCSync capability if re-enabled, with no further action required from an attacker who controls it.",
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewReplicaDirectoryChangesOnDisabledAccountDetector())
}
