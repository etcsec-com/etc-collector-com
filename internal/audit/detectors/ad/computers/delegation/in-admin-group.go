package delegation

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// InAdminGroupDetector checks for computers in admin groups
type InAdminGroupDetector struct {
	audit.BaseDetector
}

// NewInAdminGroupDetector creates a new detector
func NewInAdminGroupDetector() *InAdminGroupDetector {
	return &InAdminGroupDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_IN_ADMIN_GROUP", audit.CategoryComputers),
	}
}

// inAdminGroupSIDSuffixes is the administrative subset of the protected
// groups listed in Microsoft Learn, "Appendix C: Protected Accounts and
// Groups in Active Directory" (learn.microsoft.com/en-us/windows-server/
// identity/ad-ds/plan/security-best-practices/
// appendix-c--protected-accounts-and-groups-in-active-directory), matched by
// RID SUFFIX (via privgroups.DNsBySIDSuffix) rather than by CN: a group's
// SID is identical in every forest regardless of localization (e.g.
// "Administrateurs du schéma" in fr-FR) or of a same-named decoy group
// placed anywhere in the directory (measured live: a homonym CN "Server
// Operators" outside CN=Builtin, ordinary RID, made a prior name-matching
// version of a sibling detector flag an unrelated computer as critical -
// reproduced for this detector too, §0 of docs/security-validation/results/
// computer-in-admin-group-v2/VERDICT.md). RID values cross-checked against
// internal/audit/wellknown_sids.go and Microsoft Learn, "Security
// identifiers" (learn.microsoft.com/en-us/windows-server/identity/ad-ds/
// manage/understand-security-identifiers), fetched 2026-09-25.
//
// The appendix lists 15 protected entries; four are deliberately excluded
// here:
//   - "Read-only Domain Controllers" (-521): measured zero ACE for this
//     exact group, on either DS-Replication-Get-Changes or -All, on the
//     domain root - unlike "Domain Controllers" below. An individual RODC
//     never carries -521 in MemberOf either; its own replication identity
//     runs through "Enterprise Read-only Domain Controllers", a different,
//     forest-computed group, not through explicit membership of -521.
//   - "Replicator" (S-1-5-32-552): a legacy File Replication Service trust
//     group, a different risk category from administrative privilege.
//   - "Administrator" and "Krbtgt" are individual protected ACCOUNTS in
//     that appendix, not groups a computer object can be a MemberOf.
//
// "Domain Controllers" (-516) IS included. A prior version of this comment
// excluded it too, for a reason measured false: "every DC/RODC computer
// account is a member of its own group by design" - live measurement across
// several domain controllers, two forests, found every one of them carries
// -516 through primaryGroupID only, NEVER through MemberOf (which this
// detector, and the SID resolution it calls, is the only thing that reads).
// So the original exclusion never protected a real DC from anything; it
// only left a real gap open. -516 holds DS-Replication-Get-Changes-All on
// the domain root (an ACE read at the schema's rightsGuid, not assumed),
// and it is one of the appendix's protected groups, exactly like the ten
// below. An active, non-DC computer added to it explicitly - the only way
// this detector could ever see -516 in MemberOf, since a real DC never puts
// it there - went unflagged by this detector and by every other detector in
// the product before this fix: measured live by adding such a computer and
// diffing a full audit run, the only key that moved was a generic "privileged
// group changed in the last 7 days" info-level key, which says nothing about
// which group or why it matters and ages out in a week. See
// docs/security-validation/results/computer-in-admin-group-v3/VERDICT.md for
// the full ACE readout and the plant that established this.
//
// A prior version of this detector matched by CN prefix and only covered
// 10 of these group names (a strict subset of this set); the fix here is
// the SID resolution, not the set of groups covered.
var inAdminGroupSIDSuffixes = []string{
	"-548", // Account Operators
	"-544", // Administrators
	"-551", // Backup Operators
	"-512", // Domain Admins
	"-516", // Domain Controllers
	"-519", // Enterprise Admins
	"-527", // Enterprise Key Admins
	"-526", // Key Admins
	"-550", // Print Operators
	"-518", // Schema Admins
	"-549", // Server Operators
}

// Detect executes the detection
func (d *InAdminGroupDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	adminDNs := privgroups.DNsBySIDSuffix(data, inAdminGroupSIDSuffixes)

	for _, c := range data.Computers {
		// A disabled computer account cannot authenticate ([MS-KILE] "Check
		// Account Policy for Every TGT Request" - KDC_ERR_CLIENT_REVOKED),
		// so it cannot exercise the privilege while disabled - reported
		// separately, at Low, by
		// InAdminGroupOnDisabledAccountDetector in this same package.
		if c.Disabled {
			continue
		}
		if len(c.MemberOf) > 0 && privgroups.IsMemberOfAny(c.MemberOf, adminDNs) {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Computer in Admin Group",
		Description: "Enabled computer account is a direct member of a privileged group protected by AdminSDHolder (Domain Admins, Enterprise Admins, Administrators, Schema Admins, Account/Backup/Print/Server Operators, Key/Enterprise Key Admins, Domain Controllers), matched by SID so a same-named decoy group or a localized forest cannot hide or fake this membership. Domain Admins, Enterprise Admins and Administrators give direct domain compromise; the other groups give a documented escalation path through AD administration, DC replication or key-trust rights, and how exploitable it is depends on what else that group can reach in this directory. Disabled computer accounts in these groups are reported separately by COMPUTER_IN_ADMIN_GROUP_ON_DISABLED_ACCOUNT.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewInAdminGroupDetector())
}
