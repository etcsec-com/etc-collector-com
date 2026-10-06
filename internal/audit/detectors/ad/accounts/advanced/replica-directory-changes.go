package advanced

import (
	"context"
	"sort"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ReplicaDirectoryChangesDetector detects active accounts that can perform
// DCSync. Disabled accounts holding the same rights are
// reported separately, at Low, by
// ReplicaDirectoryChangesOnDisabledAccountDetector (same split convention as
// admin-count-orphaned.go / admin-count-orphaned-on-disabled-account.go).
type ReplicaDirectoryChangesDetector struct {
	audit.BaseDetector
}

// NewReplicaDirectoryChangesDetector creates a new detector
func NewReplicaDirectoryChangesDetector() *ReplicaDirectoryChangesDetector {
	return &ReplicaDirectoryChangesDetector{
		BaseDetector: audit.NewBaseDetector("REPLICA_DIRECTORY_CHANGES", audit.CategoryAccounts),
	}
}

// replicaRightsHolder tracks, per trustee, which of the two rights required
// for DCSync have been granted by at least one ACE on the domain root.
type replicaRightsHolder struct {
	getChanges    bool
	getChangesAll bool
}

// replicaRootHolders scans data.ACLEntries for grant ACEs on the domain root
// and returns the indices (into data.Users) of every non-built-in-admin user
// who holds BOTH DS-Replication-Get-Changes AND DS-Replication-Get-Changes-All
// - the pair actually required to perform DCSync (Microsoft Learn, Win32 AD
// Schema reference, "DS-Replication-Get-Changes[-All] extended right":
// learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes
// and .../r-ds-replication-get-changes-all). Holding only one right is not
// enough to run DCSync and is deliberately not counted.
//
// Each individual right can be granted three equivalent ways, all counted:
//   - a CONTROL_ACCESS (types.MaskControlAccess) ACE naming that right's GUID
//     as ObjectType - the direct grant;
//   - a CONTROL_ACCESS ACE with an EMPTY ObjectType: AD's ACE model grants an
//     ACE with the CONTROL_ACCESS bit set and no ObjectType as every extended
//     right at once, replication rights included (same convention documented
//     on internal/audit/aclentry.go's GrantsApplyGroupPolicy - a forbidden
//     shared file for this ticket, so the rule is re-derived here rather than
//     imported);
//   - GenericAll, which subsumes every other right including CONTROL_ACCESS.
//
// The two rights may arrive on two separate ACEs (the common case), or both
// be satisfied by a single ACE that grants an equivalent (GenericAll, or
// CONTROL_ACCESS with no ObjectType) - types.ACLEntry carries exactly one
// ObjectType per ACE, so a single ACE naming BOTH specific right GUIDs at
// once is not representable in this data model and is not a case this
// function needs to handle.
//
// Declared limitations, not handled here:
//   - WriteDACL and WriteOwner are NOT counted. Both can *lead* to DCSync,
//     but only by first rewriting the domain root's ACL to add one of the
//     rights above - an escalation step, not present possession of the
//     right. That is a distinct attack path already covered by the
//     permissions-family ACL detectors, not this one.
//   - Explicit ACCESS_DENIED ACEs on these rights are not modeled to cancel a
//     separate ACCESS_ALLOWED grant elsewhere in the same DACL. Real AD
//     evaluates ACEs in the DACL's stored order, and canonical ordering
//     places denies before allows at the same level - but types.ACLEntry
//     does not preserve that order, so precedence cannot be reconstructed
//     from this data. audit.IsGrantACE already guarantees a deny ACE is
//     never itself read as a grant; a holder who ALSO carries an explicit
//     deny elsewhere is still counted as a holder here.
//   - Only data.Users is consulted: a trustee SID with no matching entry in
//     userBySID is skipped even if it grants both rights. Groups and
//     computers can hold these rights too; extending the population is out
//     of scope for this ticket (see the ticket body).
//   - An ACE carrying the INHERIT_ONLY flag (AceFlags & 0x08, types.ACLEntry's
//     InheritOnly field) is ignored, per MS-ADTS 3.1 Checking Control Access
//     Right-Based Access: such an ACE does not apply to the object it is set
//     on, only to descendants that inherit it, so it grants nothing on the
//     domain root itself.
//
// Returns holders regardless of Disabled: callers partition by that field
// themselves (mirrors admin-count-orphaned.go's protectedGroupSIDSuffixes /
// isProtectedAccountRID, shared by both detectors of that split family).
func replicaRootHolders(data *audit.DetectorData) map[int]bool {
	var domainDN string
	if data.DomainInfo != nil {
		domainDN = strings.ToLower(data.DomainInfo.DomainDN)
		if domainDN == "" {
			domainDN = strings.ToLower(data.DomainInfo.DN)
		}
	}
	if domainDN == "" {
		return nil
	}

	userBySID := make(map[string]int, len(data.Users))
	for i := range data.Users {
		if data.Users[i].ObjectSID != "" {
			userBySID[data.Users[i].ObjectSID] = i
		}
	}

	getChangesGUID := strings.ToLower(types.GUIDDSReplicationGetChanges)
	getChangesAllGUID := strings.ToLower(types.GUIDDSReplicationGetChangesAll)

	held := make(map[string]*replicaRightsHolder)

	for _, ace := range data.ACLEntries {
		if strings.ToLower(ace.ObjectDN) != domainDN {
			continue
		}
		if ace.InheritOnly {
			continue // MS-ADTS 3.1: does not apply to the object it is set on, only to descendants
		}
		if !audit.IsGrantACE(ace.AceType) {
			continue
		}
		if audit.IsBuiltinAdminTrustee(ace.Trustee) {
			continue // Domain Controllers / Domain Admins / Enterprise Admins etc. hold this by default
		}
		if _, ok := userBySID[ace.Trustee]; !ok {
			continue // population is users only in this ticket - see the doc comment above
		}

		var grantsGetChanges, grantsGetChangesAll bool
		switch {
		case ace.AccessMask&types.MaskGenericAll != 0:
			grantsGetChanges = true
			grantsGetChangesAll = true
		case ace.AccessMask&types.MaskControlAccess != 0:
			switch strings.ToLower(ace.ObjectType) {
			case "":
				grantsGetChanges = true
				grantsGetChangesAll = true
			case getChangesGUID:
				grantsGetChanges = true
			case getChangesAllGUID:
				grantsGetChangesAll = true
			}
		}
		if !grantsGetChanges && !grantsGetChangesAll {
			continue
		}

		r := held[ace.Trustee]
		if r == nil {
			r = &replicaRightsHolder{}
			held[ace.Trustee] = r
		}
		r.getChanges = r.getChanges || grantsGetChanges
		r.getChangesAll = r.getChangesAll || grantsGetChangesAll
	}

	holders := make(map[int]bool)
	for sid, r := range held {
		if r.getChanges && r.getChangesAll {
			holders[userBySID[sid]] = true
		}
	}
	return holders
}

// sortUsersByDN sorts affected users by DN so finding output is
// deterministic across runs - data.Users and the holders map above are
// iterated/keyed in ways that do not preserve a stable order on their own.
func sortUsersByDN(users []types.User) {
	sort.Slice(users, func(i, j int) bool {
		return strings.ToLower(users[i].DN) < strings.ToLower(users[j].DN)
	})
}

// Detect executes the detection.
func (d *ReplicaDirectoryChangesDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	holders := replicaRootHolders(data)

	var affected []types.User
	for idx := range holders {
		if data.Users[idx].Disabled {
			continue // reported separately, at Low, by ReplicaDirectoryChangesOnDisabledAccountDetector
		}
		affected = append(affected, data.Users[idx])
	}
	sortUsersByDN(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Directory Replication Rights (DCSync)",
		Description: "Active accounts hold both the DS-Replication-Get-Changes and DS-Replication-Get-Changes-All extended rights - or an equivalent grant (GenericAll, or a CONTROL_ACCESS ACE with no ObjectType, which AD grants as every extended right) - on the domain root (Microsoft Learn, Win32 AD Schema reference, \"DS-Replication-Get-Changes[-All] extended right\"). Holding only one of the two rights cannot perform DCSync and is not reported. These accounts can extract all password hashes from the domain (DCSync). Limits: only user accounts are checked - computer accounts and groups holding the rights are not, and group membership is not expanded to the users inside; an ACE flagged inherit-only (applies only to descendants, not the domain root itself) is ignored; and an explicit ACCESS_DENIED ACE elsewhere in the same ACL is not evaluated against a separate grant.",
		Count:       len(affected),
	}

	if data.IncludeDetails {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		if len(affected) > 0 {
			finding.Details = map[string]interface{}{
				"recommendation": "Review ACLs on the domain head for DS-Replication-Get-Changes[-All] and their equivalents (GenericAll, CONTROL_ACCESS with no ObjectType). Only Domain Controllers and tier-0 administrators should have these rights.",
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewReplicaDirectoryChangesDetector())
}
