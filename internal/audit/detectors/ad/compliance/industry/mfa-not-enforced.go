package industry

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// MFANotEnforcedDetector checks for MFA enforcement on privileged accounts
type MFANotEnforcedDetector struct {
	audit.BaseDetector
}

// NewMFANotEnforcedDetector creates a new detector
func NewMFANotEnforcedDetector() *MFANotEnforcedDetector {
	return &MFANotEnforcedDetector{
		BaseDetector: audit.NewBaseDetector("MFA_NOT_ENFORCED", audit.CategoryCompliance),
	}
}

// UAC flag for smartcard required
const uacSmartcardRequired = 0x40000

// privilegedRIDs are the RID suffixes (relative to the domain SID) of the
// three built-in groups this detector cares about: Domain Admins (-512),
// Schema Admins (-518), Enterprise Admins (-519). RID-based matching is
// locale-independent - on a French-installed AD these groups are named
// "Admins du domaine", "Administrateurs du schéma", "Administrateurs de
// l'entreprise", so the English-name substring match previously used here
// (memberOf DN containing "domain admins"/"schema admins"/"enterprise
// admins") silently produced totalAdmins=0 on any non-English domain. Same
// RID-suffix approach already used elsewhere in this repo, e.g.
// isAdminSID in detectors/ad/advanced/replication/dcsync-capable.go.
var privilegedRIDs = []string{"-512", "-518", "-519"}

// isPrivilegedAdmin reports whether u is a member (direct or via primary
// group) of Domain/Schema/Enterprise Admins. Direct membership is resolved
// through groupSIDByDN because u.MemberOf only carries DNs, not SIDs.
//
// PrimaryGroupID is checked separately because AD does not add a memberOf
// backlink for a user's PRIMARY group: a user whose primaryGroupID has been
// set to 512 (Domain Admins) is a full domain admin without ever appearing
// in Domain Admins' member list or in their own memberOf attribute - a
// memberOf-only scan misses them entirely.
func isPrivilegedAdmin(u types.User, groupSIDByDN map[string]string) bool {
	for _, rid := range []int{512, 518, 519} {
		if u.PrimaryGroupID == rid {
			return true
		}
	}
	for _, dn := range u.MemberOf {
		sid := groupSIDByDN[strings.ToLower(dn)]
		for _, suffix := range privilegedRIDs {
			if strings.HasSuffix(sid, suffix) {
				return true
			}
		}
	}
	return false
}

// Detect executes the detection
func (d *MFANotEnforcedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	groupSIDByDN := make(map[string]string, len(data.Groups))
	for _, g := range data.Groups {
		groupSIDByDN[strings.ToLower(g.DN)] = g.ObjectSID
	}

	// Check for privileged accounts without smartcard requirement
	var adminsWithoutMFAList []types.User
	totalAdmins := 0

	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}

		if isPrivilegedAdmin(u, groupSIDByDN) {
			totalAdmins++
			smartcardRequired := (u.UserAccountControl & uacSmartcardRequired) != 0
			if !smartcardRequired {
				adminsWithoutMFAList = append(adminsWithoutMFAList, u)
			}
		}
	}

	adminsWithoutMFA := len(adminsWithoutMFAList)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "MFA Not Enforced for Privileged Accounts",
		Description: "Multi-factor authentication is not enforced for all privileged accounts. Smartcard requirement should be enabled for admin accounts.",
		Count:       0,
		Details: map[string]interface{}{
			"category":         "Industry Best Practices",
			"totalAdmins":      totalAdmins,
			"adminsWithoutMFA": adminsWithoutMFA,
		},
	}

	if adminsWithoutMFA > 0 {
		finding.Count = adminsWithoutMFA
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedUserEntities(adminsWithoutMFAList)
		}
		finding.Details["recommendations"] = []string{
			"Enable 'Smart card is required for interactive logon' for all admin accounts",
			"Implement Azure AD Conditional Access with MFA for cloud-integrated environments",
			"Use Windows Hello for Business as an alternative MFA method",
			"Consider third-party MFA solutions for comprehensive coverage",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewMFANotEnforcedDetector())
}
