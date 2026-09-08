package delegation

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
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

// adminGroups is the administrative subset of the protected groups listed
// in Microsoft Learn, "Appendix C: Protected Accounts and Groups in Active
// Directory" (learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/
// security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory).
// The appendix lists 15 entries; five are deliberately excluded here:
//   - "Domain Controllers" / "Read-only Domain Controllers": every DC/RODC
//     computer account is a member of its own group by design. That is
//     expected structure, not an anomaly - including them would flag every
//     domain's own domain controllers.
//   - "Replicator": a legacy File Replication Service trust group, a
//     different risk category from administrative privilege.
//   - "Administrator" and "Krbtgt" are individual protected ACCOUNTS in
//     that appendix, not groups a computer object can be a MemberOf.
//
// A prior version of this detector only checked 2 of these 15
// (Domain Admins, Enterprise Admins).
var adminGroups = []string{
	"Account Operators",
	"Administrators",
	"Backup Operators",
	"Domain Admins",
	"Enterprise Admins",
	"Enterprise Key Admins",
	"Key Admins",
	"Print Operators",
	"Schema Admins",
	"Server Operators",
}

// inAdminGroup reports whether memberOf contains one of the named groups.
// It anchors on "cn=<group>," as a DN prefix rather than an unanchored
// substring match, so a group actually named e.g. "Administrators2" isn't
// mistaken for "Administrators" (the prior strings.Contains(memberOf,
// "CN="+group) check had exactly that false-match risk).
func inAdminGroup(memberOf []string, groups []string) bool {
	for _, dn := range memberOf {
		lowerDN := strings.ToLower(dn)
		for _, g := range groups {
			if strings.HasPrefix(lowerDN, "cn="+strings.ToLower(g)+",") {
				return true
			}
		}
	}
	return false
}

// Detect executes the detection
func (d *InAdminGroupDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		// A prior version's nested loop appended a computer once per
		// matching (memberOf entry × adminGroup) pair rather than once per
		// computer, only breaking the innermost loop. A computer in both
		// Domain Admins and Enterprise Admins was counted (and reported)
		// twice.
		if inAdminGroup(c.MemberOf, adminGroups) {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Computer in Admin Group",
		Description: "Computer account is a member of a privileged group protected by AdminSDHolder (Domain Admins, Enterprise Admins, Administrators, Schema Admins, Account/Backup/Print/Server Operators, Key/Enterprise Key Admins). Computer compromise leads to domain admin access.",
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
