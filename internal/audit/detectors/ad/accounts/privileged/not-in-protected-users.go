package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NO_PROTECTED_USERS_MONITORING (monitoring/protected-users.go) once lived
// alongside this detector with the same claim ("privileged account missing
// from Protected Users"), a plain adminCount-only eligibility test and no
// exclusions. On DC01 it produced this detector's exact 4 accounts plus 3
// more (the built-in Administrator, and two SPN-bearing service accounts)
// that CANNOT be added to Protected Users without breaking authentication or
// Kerberos delegation - its extra "findings" were false positives this
// detector's exclusions (below) exist specifically to prevent. Removed; it
// carried no compliance mapping, so removing it costs nothing (dedup.go, R4).
// See detectors/ad/dedup.go.

// NotInProtectedUsersDetector detects privileged accounts not in Protected Users group
type NotInProtectedUsersDetector struct {
	audit.BaseDetector
}

// NewNotInProtectedUsersDetector creates a new detector
func NewNotInProtectedUsersDetector() *NotInProtectedUsersDetector {
	return &NotInProtectedUsersDetector{
		BaseDetector: audit.NewBaseDetector("NOT_IN_PROTECTED_USERS", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *NotInProtectedUsersDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	// protectedUsersDNs is the DN of every collected group whose SID ends in
	// the well-known Protected Users RID (-525, Microsoft Learn "Security
	// identifiers"), resolved the same non-localized, non-homonym-prone way
	// privgroups already resolves the 7 privileged groups below: a group
	// merely named "Protected Users" grants no real protection, and the real
	// group under a renamed/localized CN is still recognized.
	protectedUsersDNs := privgroups.DNsBySIDSuffix(data, []string{"-525"})

	// If no group carries the -525 RID (pre-2012R2 domain, or its SID never
	// made it into the collected index), the detector stays silent - same
	// behavior as the previous by-name lookup's miss case. This is a known
	// limitation, not a proof of a healthy domain: see
	// docs/security-validation/results/not-in-protected-users-v2/VERDICT.md §8.
	if len(protectedUsersDNs) == 0 {
		return []types.Finding{}
	}

	// protectedUsersMembers is the member DN set of every group identified
	// above, read straight from data.Groups: DNsBySIDSuffix only resolves a
	// group's own DN, not its Member list.
	protectedUsersMembers := make(map[string]bool)
	for i := range data.Groups {
		if protectedUsersDNs[strings.ToLower(data.Groups[i].DN)] {
			for _, m := range data.Groups[i].Member {
				protectedUsersMembers[strings.ToLower(m)] = true
			}
		}
	}

	// privilegedGroupSIDSuffixes is the same 7 groups this detector always
	// used (Domain Admins, Enterprise Admins, Schema Admins, Administrators,
	// Account Operators, Backup Operators, Server Operators), matched by RID
	// suffix instead of CN: a homonym group grants no real
	// membership, and a renamed real group is still caught. All 7 suffixes
	// already appear in types.PrivilegedSIDSuffixes.
	privilegedGroupSIDSuffixes := []string{"-512", "-519", "-518", "-544", "-548", "-551", "-549"}
	privilegedDNs := privgroups.DNsBySIDSuffix(data, privilegedGroupSIDSuffixes)

	for _, u := range data.Users {
		if u.Disabled {
			continue
		}

		// Check if privileged
		isPrivileged := false

		// Criterion 1: AdminCount=true
		if u.AdminCount {
			isPrivileged = true
		}

		// Criterion 2: Member of privileged groups
		if !isPrivileged && len(u.MemberOf) > 0 {
			isPrivileged = privgroups.IsMemberOfAny(u.MemberOf, privilegedDNs)
		}

		if !isPrivileged {
			continue
		}

		// Exclusions by well-known RID (Microsoft Learn "Security
		// identifiers"): krbtgt (-502) and the built-in Administrator
		// (-500) can be renamed, so their SAMAccountName is not a reliable
		// signal in either direction - only the RID is.
		if strings.HasSuffix(u.ObjectSID, "-502") {
			continue
		}
		if strings.HasSuffix(u.ObjectSID, "-500") {
			continue
		}
		if len(u.ServicePrincipalNames) > 0 {
			continue // Service accounts incompatible with Protected Users
		}

		// Check if in Protected Users (both methods, both by resolved DN)

		// Method 1: Check user's MemberOf
		isInProtectedUsers := privgroups.IsMemberOfAny(u.MemberOf, protectedUsersDNs)

		// Method 2: Check group's member list
		if !isInProtectedUsers && protectedUsersMembers[strings.ToLower(u.DN)] {
			isInProtectedUsers = true
		}

		if !isInProtectedUsers {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Privileged Accounts Not in Protected Users",
		Description: "Privileged accounts not in Protected Users group. Missing enhanced security protections (NTLM disabled, no Kerberos delegation, no credential caching).",
		Count:       len(affected),
		Details: map[string]interface{}{
			"recommendation": "Add privileged accounts to Protected Users group",
			"exclusions":     "Service accounts with SPNs excluded (incompatible)",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNotInProtectedUsersDetector())
}
