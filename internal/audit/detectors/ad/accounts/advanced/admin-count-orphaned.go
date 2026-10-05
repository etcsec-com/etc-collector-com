package advanced

import (
	"context"
	"strconv"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminCountOrphanedDetector detects active users with adminCount=1 but not
// in any privileged group, by memberOf nor by primary group. Disabled
// accounts are reported separately, at Low, by
// AdminCountOrphanedOnDisabledAccountDetector.
type AdminCountOrphanedDetector struct {
	audit.BaseDetector
}

// NewAdminCountOrphanedDetector creates a new detector
func NewAdminCountOrphanedDetector() *AdminCountOrphanedDetector {
	return &AdminCountOrphanedDetector{
		BaseDetector: audit.NewBaseDetector("ADMIN_COUNT_ORPHANED", audit.CategoryAccounts),
	}
}

// protectedGroupSIDSuffixes is the group half of Microsoft Learn, "Appendix C:
// Protected Accounts and Groups in Active Directory"
// (learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/
// security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory).
// The appendix lists 15 protected objects; 13 are groups a user can actually
// appear in via memberOf. The remaining 2 ("Administrator" and "Krbtgt")
// are individual protected ACCOUNTS, not groups - membership in them is not
// a thing, so they can't be used to explain another user's adminCount and
// are handled separately below via protectedAccountRIDSuffixes.
//
// The previous list here only covered 8 of the 13 groups, missing Domain
// Controllers, Read-only Domain Controllers, Replicator, Key Admins and
// Enterprise Key Admins - a user whose adminCount=1 was legitimately set by
// SDProp because of membership in one of those five was wrongly reported as
// "orphaned".
//
// Matched by RID suffix (privgroups.DNsBySIDSuffix), not by CN, so
// a group homonym with no real privilege can no longer explain an
// adminCount=1, and a real protected group renamed on a non-English forest
// is still recognized. Same 13 groups as before, unchanged; suffixes read
// from Microsoft Learn "Security Identifiers"
// (learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/
// understand-security-identifiers), cross-checked against
// types.PrivilegedSIDSuffixes for the 11 it already carries.
var protectedGroupSIDSuffixes = []string{
	"-548", // Account Operators
	"-544", // Administrators
	"-551", // Backup Operators
	"-512", // Domain Admins
	"-516", // Domain Controllers
	"-519", // Enterprise Admins
	"-527", // Enterprise Key Admins
	"-526", // Key Admins
	"-550", // Print Operators
	"-521", // Read-only Domain Controllers
	"-552", // Replicator
	"-518", // Schema Admins
	"-549", // Server Operators
}

// protectedAccountRIDSuffixes are the two individual accounts Appendix C
// protects directly (as opposed to via group membership): krbtgt (-502) and
// the built-in Administrator (-500). adminCount=1 on either is expected,
// by-design AdminSDHolder/SDProp behavior, never an "orphaned" flag - SDProp
// protects them regardless of what they are (or aren't) a memberOf.
//
// Matched by RID suffix on u.ObjectSID (same idiom as
// accounts/privileged/not-in-protected-users.go), never by SAMAccountName: a
// common hardening step renames the built-in Administrator account, which
// would escape a name-based check, while an ordinary account named
// "administrator" carries no protection at all and must not be exempted
// just because of its name.
var protectedAccountRIDSuffixes = []string{"-500", "-502"}

func isProtectedAccountRID(objectSID string) bool {
	for _, suffix := range protectedAccountRIDSuffixes {
		if strings.HasSuffix(objectSID, suffix) {
			return true
		}
	}
	return false
}

// primaryGroupIsProtected reports whether u's PRIMARY group - not memberOf;
// AD never adds a memberOf backlink for a user's primary group, so it must
// be checked separately - is one of the protected groups in
// protectedGroupDNs (as built from protectedGroupSIDSuffixes).
// u.PrimaryGroupID (providers/ldap/parser.go's parseUser, off the wire
// "primaryGroupID" attribute) is a bare RID, relative to the domain; it is
// turned into a full SID by prefixing data.DomainInfo.DomainSID and looked
// up directly (exact match, not suffix) in data.ObjectBySID.
//
// The exact-match lookup is what keeps this safe against
// accounts/patterns/primarygroupid-spoofing.go's attack: AD only ever
// accepts a global or universal group the user already belongs to as its
// primary group, so the legitimate values are limited to Domain Admins
// (-512), Domain Controllers (-516), Schema Admins (-518), Enterprise
// Admins (-519), Read-only Domain Controllers (-521), Key Admins (-526) and
// Enterprise Key Admins (-527). The domain-local builtins also present in
// protectedGroupSIDSuffixes (Administrators -544 chief among them) carry the
// fixed "S-1-5-32-*" prefix, never the domain SID, so a spoofed
// primaryGroupID of 544 builds a SID that cannot match any real object here
// and grants no exemption.
//
// When data.DomainInfo or its DomainSID is empty (not collected), no
// exemption is granted here: this fails CLOSED (the account can still be
// exempted through memberOf), never open, rather than trusting an
// unverifiable RID.
func primaryGroupIsProtected(data *audit.DetectorData, u types.User, protectedGroupDNs map[string]bool) bool {
	if data.DomainInfo == nil || data.DomainInfo.DomainSID == "" {
		return false
	}
	primaryGroupSID := data.DomainInfo.DomainSID + "-" + strconv.Itoa(u.PrimaryGroupID)
	meta := data.ObjectBySID[primaryGroupSID]
	if meta == nil {
		return false
	}
	return protectedGroupDNs[strings.ToLower(meta.DN)]
}

// Detect executes the detection
func (d *AdminCountOrphanedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	protectedGroupDNs := privgroups.DNsBySIDSuffix(data, protectedGroupSIDSuffixes)

	for _, u := range data.Users {
		// Must have adminCount=true
		if !u.AdminCount {
			continue
		}

		// Disabled accounts are reported separately, at Low, by
		// AdminCountOrphanedOnDisabledAccountDetector - they carry the same
		// residual-privilege question but a materially lower urgency, since
		// a disabled account cannot currently authenticate.
		if u.Disabled {
			continue
		}

		// krbtgt and the built-in Administrator account are protected
		// directly by AdminSDHolder/SDProp (Appendix C), independent of any
		// group membership. adminCount=1 on them is normal and expected -
		// never an orphan, regardless of what memberOf shows.
		if isProtectedAccountRID(u.ObjectSID) {
			continue
		}

		// A protected PRIMARY group explains adminCount=1 exactly as a
		// protected memberOf entry would - AD just doesn't record it as a
		// memberOf backlink. Checked once, ahead of both branches below, so
		// it covers "no memberOf at all" and "memberOf present but none of
		// it protected" the same way.
		if primaryGroupIsProtected(data, u, protectedGroupDNs) {
			continue
		}

		// Check if actually in a protected group
		if len(u.MemberOf) == 0 {
			// adminCount but no protected direct memberOf and no protected
			// primary group
			affected = append(affected, u)
			continue
		}

		// Check if in any protected group. Note: this (and the primary-group
		// check above) only inspects DIRECT membership. AdminSDHolder/SDProp
		// also protects accounts reached via NESTED group membership (e.g. a
		// user in a group that is itself a member of Domain Admins, or whose
		// primary group is itself a member of a protected group) - that case
		// is not resolved here and can still produce a false "orphaned"
		// positive. This is a known, documented limitation, not an
		// assumed-safe design choice; resolving it needs group-membership
		// expansion (see helpers.Tier0Members/expandGroupMembers for the
		// recursive approach used elsewhere), which is out of scope for this
		// fix.
		if !privgroups.IsMemberOfAny(u.MemberOf, protectedGroupDNs) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Orphaned AdminCount Flag",
		Description: "Active accounts with adminCount=1 that are not a DIRECT member - via memberOf or primary group - of any group AdminSDHolder/SDProp protects (Microsoft Learn, \"Appendix C: Protected Accounts and Groups in Active Directory\", https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory), and are not krbtgt or the built-in Administrator account (identified by RID, not name). May indicate a removed admin that still carries residual privileges, or intact SDProp protection. Limitation: membership reached through a NESTED group - a group that is itself a member of a protected group, or a primary group that is itself nested - is not resolved and can still produce a false positive here.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Verify there is no NESTED protected-group membership (direct membership and primary group are already ruled out) before clearing the adminCount flag; only then reset ACLs to allow proper inheritance.",
			"impact":         "Accounts may still have protected ACLs preventing proper management.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminCountOrphanedDetector())
}
