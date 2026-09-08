package advanced

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminCountOrphanedDetector detects users with adminCount=1 but not in admin groups
type AdminCountOrphanedDetector struct {
	audit.BaseDetector
}

// NewAdminCountOrphanedDetector creates a new detector
func NewAdminCountOrphanedDetector() *AdminCountOrphanedDetector {
	return &AdminCountOrphanedDetector{
		BaseDetector: audit.NewBaseDetector("ADMIN_COUNT_ORPHANED", audit.CategoryAccounts),
	}
}

// protectedGroups is the group half of Microsoft Learn, "Appendix C:
// Protected Accounts and Groups in Active Directory"
// (learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/
// security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory).
// The appendix lists 15 protected objects; 13 are groups a user can actually
// appear in via memberOf. The remaining 2 ("Administrator" and "Krbtgt")
// are individual protected ACCOUNTS, not groups - membership in them is not
// a thing, so they can't be used to explain another user's adminCount and
// are handled separately below via protectedAccountNames.
//
// The previous list here only covered 8 of the 13 groups, missing Domain
// Controllers, Read-only Domain Controllers, Replicator, Key Admins and
// Enterprise Key Admins - a user whose adminCount=1 was legitimately set by
// SDProp because of membership in one of those five was wrongly reported as
// "orphaned".
var protectedGroups = []string{
	"Account Operators",
	"Administrators",
	"Backup Operators",
	"Domain Admins",
	"Domain Controllers",
	"Enterprise Admins",
	"Enterprise Key Admins",
	"Key Admins",
	"Print Operators",
	"Read-only Domain Controllers",
	"Replicator",
	"Schema Admins",
	"Server Operators",
}

// protectedAccountNames are the individual accounts Appendix C protects
// directly (as opposed to via group membership). adminCount=1 on either of
// these is expected, by-design AdminSDHolder/SDProp behavior, never an
// "orphaned" flag - SDProp protects them regardless of what they are (or
// aren't) a memberOf.
var protectedAccountNames = []string{"krbtgt", "administrator"}

func isProtectedAccountName(sam string) bool {
	for _, n := range protectedAccountNames {
		if strings.EqualFold(sam, n) {
			return true
		}
	}
	return false
}

// Detect executes the detection
func (d *AdminCountOrphanedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Must have adminCount=true
		if !u.AdminCount {
			continue
		}

		// krbtgt and the built-in Administrator account are protected
		// directly by AdminSDHolder/SDProp (Appendix C), independent of any
		// group membership. adminCount=1 on them is normal and expected -
		// never an orphan, regardless of what memberOf shows.
		if isProtectedAccountName(u.SAMAccountName) {
			continue
		}

		// Check if actually in a protected group
		if len(u.MemberOf) == 0 {
			// adminCount but no group membership
			affected = append(affected, u)
			continue
		}

		// Check if in any protected group. Note: this only inspects DIRECT
		// memberOf entries. AdminSDHolder/SDProp also protects accounts
		// reached via NESTED group membership (e.g. a user in a group that
		// is itself a member of Domain Admins) - that case is not resolved
		// here and can still produce a false "orphaned" positive. This is a
		// known, documented limitation, not an assumed-safe design choice;
		// resolving it needs group-membership expansion (see
		// helpers.Tier0Members/expandGroupMembers for the recursive
		// approach used elsewhere), which is out of scope for this fix.
		if !helpers.IsInAnyGroup(u.MemberOf, protectedGroups) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Orphaned AdminCount Flag",
		Description: "Accounts with adminCount=1 but not in any privileged group. This may indicate removed admins that still have residual privileges or SDProp protection.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Review these accounts. If no longer admins, clear adminCount flag and reset ACLs to allow proper inheritance.",
			"impact":         "Accounts may still have protected ACLs preventing proper management.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminCountOrphanedDetector())
}
