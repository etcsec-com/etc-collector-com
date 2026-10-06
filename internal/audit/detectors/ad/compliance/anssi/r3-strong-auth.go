package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R3StrongAuthDetector checks strong-authentication enforcement for
// privileged accounts.
//
// A full-text audit of ANSSI PA-099 found no "R3" (nor any other
// R-number) in that guide mandating strong/smartcard authentication for
// admin accounts - PA-099 explicitly defers the whole subject to a separate
// ANSSI publication: "Pour plus d'information, se référer au guide
// « Authentification multifacteur et mots de passe » [2] de l'ANSSI." The
// "R3" in this detector's ID/title was internal legacy numbering, not a
// PA-099 citation - the ID is kept for stability, but no ANSSI PA-099
// recommendation is claimed here.
type R3StrongAuthDetector struct {
	audit.BaseDetector
}

// NewR3StrongAuthDetector creates a new detector
func NewR3StrongAuthDetector() *R3StrongAuthDetector {
	return &R3StrongAuthDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R3_STRONG_AUTH", audit.CategoryCompliance),
	}
}

// UAC flag for smartcard required
const uacSmartcardRequired = 0x40000

// privilegedAdminRIDs are the RID suffixes (relative to the domain SID) of
// Domain Admins (-512), Schema Admins (-518) and Enterprise Admins (-519).
var privilegedAdminRIDs = []string{"-512", "-518", "-519"}

// isPrivilegedAdmin reports whether u is a privileged administrator: either
// flagged by AdminSDHolder (AdminCount=1, the population most of this
// package's detectors already use), OR a member - direct or via primary
// group - of Domain/Schema/Enterprise Admins by RID, independent of
// AdminCount.
//
// AdminCount=1 alone has two known gaps: it's an "orphan" flag (stays 1
// forever after a first-and-only stint in a protected group, per PA-099
// R23's footnote 16, so it over-includes former admins) and it is stamped
// by AdminSDHolder on a timer (roughly hourly by default), so a JUST-added
// Domain Admin can have AdminCount still at 0 for up to that interval,
// under-including a real current admin. Cross-checking group SID/RID
// membership closes the under-inclusion side; groupSIDByDN resolves
// u.MemberOf (DNs only) to SIDs since AD does not add a memberOf backlink
// for a user's PRIMARY group, PrimaryGroupID is checked separately.
func isPrivilegedAdmin(u types.User, groupSIDByDN map[string]string) bool {
	if u.AdminCount {
		return true
	}
	for _, rid := range []int{512, 518, 519} {
		if u.PrimaryGroupID == rid {
			return true
		}
	}
	for _, dn := range u.MemberOf {
		sid := groupSIDByDN[strings.ToLower(dn)]
		for _, suffix := range privilegedAdminRIDs {
			if strings.HasSuffix(sid, suffix) {
				return true
			}
		}
	}
	return false
}

// Detect executes the detection
func (d *R3StrongAuthDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	groupSIDByDN := make(map[string]string, len(data.Groups))
	for _, g := range data.Groups {
		groupSIDByDN[strings.ToLower(g.DN)] = g.ObjectSID
	}

	// Privileged population: AdminCount=1 alone both over-includes (an
	// "orphan" AdminCount from a past-only stint in a protected group never
	// clears itself) and under-includes (AdminSDHolder stamps AdminCount on
	// a timer, so a just-added Domain Admin can read AdminCount=0 for up to
	// that interval). isPrivilegedAdmin also cross-checks direct/primary-
	// group Domain/Schema/Enterprise Admins membership by RID, closing the
	// under-inclusion side.
	//
	// Strong-auth modality: the previous version only accepted the
	// smartcard-required UAC bit, flagging admins protected by Windows
	// Hello for Business or FIDO2 (msDS-KeyCredentialLink) as if they had no
	// strong authentication at all.
	var adminsWithoutStrongAuth []types.User
	for _, u := range data.Users {
		if !u.Enabled() || !isPrivilegedAdmin(u, groupSIDByDN) {
			continue
		}
		smartcardRequired := (u.UserAccountControl & uacSmartcardRequired) != 0
		hasKeyCredential := len(u.KeyCredentialLink) > 0
		if !smartcardRequired && !hasKeyCredential {
			adminsWithoutStrongAuth = append(adminsWithoutStrongAuth, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Strong Authentication Not Enforced for Privileged Accounts",
		Description: "Privileged accounts should require strong authentication (smartcard, Windows Hello for Business, or a FIDO2 security key) instead of a password alone. Recognized as a best practice by ANSSI's hygiene guide (measure M13, \"privilégier lorsque cela est possible une authentification forte\"); not a PA-099 requirement.",
		Count:       0,
	}

	if len(adminsWithoutStrongAuth) > 0 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"violations":              []string{"Privileged accounts without strong authentication (smartcard, WHfB, or FIDO2)"},
			"adminsWithoutStrongAuth": len(adminsWithoutStrongAuth),
		}
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedUserEntities(adminsWithoutStrongAuth)
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewR3StrongAuthDetector())
}
