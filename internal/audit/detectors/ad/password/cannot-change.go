package password

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CannotChangeDetector detects accounts forbidden from changing their password
type CannotChangeDetector struct {
	audit.BaseDetector
}

// NewCannotChangeDetector creates a new detector
func NewCannotChangeDetector() *CannotChangeDetector {
	return &CannotChangeDetector{
		BaseDetector: audit.NewBaseDetector("USER_CANNOT_CHANGE_PASSWORD", audit.CategoryPassword),
	}
}

// Trustees whose Deny ACE on the Change-Password extended right blocks an
// account from changing its own password. Everyone (S-1-1-0) is present in
// every access token, including the one built for the account's own
// self-change bind; NT AUTHORITY\SELF (S-1-5-10) is the placeholder that
// resolves to the object the ACE sits on. Either one alone is sufficient:
// see the Detect doc comment below for why this detector requires only one,
// not both.
const (
	sidEveryone = "S-1-1-0"
	sidSelf     = "S-1-5-10"
)

// Detect executes the detection.
//
// (userAccountControl & 0x0040) can never be true on a real LDAP read
// (ADS_UF_PASSWD_CANT_CHANGE only ever existed on the legacy SAM-backed
// WinNT provider) - established by plant/revert on DC01, full measurements
// in VERDICT.md. The real, documented representation of the
// state is two Deny ACEs on the User-Change-Password extended right
// (types.GUIDChangePassword, {AB721A53-1E2F-11D0-9819-00AA0040529B}, read
// from CN=Extended-Rights of the lab forest, not retyped - see VERDICT.md),
// one for Everyone (S-1-1-0) and one for NT AUTHORITY\SELF (S-1-5-10), in
// the object's own DACL - exactly the ACE shape data.ACLEntries already
// carries for every user (engine.go passes every user DN to GetACLs).
//
// PROVEN: the GUID above is correct at the source; AceType for a denied
// object ACE is literally "ACCESS_DENIED_OBJECT" (acl_parser.go's
// aceTypeToString, case aceTypeAccessDeniedObject) and Trustee arrives as a
// raw SID string, e.g. "S-1-1-0" (parseSID), never a resolved name - both
// established by reading the parser, not assumed. The condition below
// requires only ONE of the two documented trustees to be denied, not both:
// under the standard Windows ACL evaluation algorithm (MS-DTYP 2.5.3),
// explicit Deny ACEs are evaluated before Allow ACEs for a matching SID in
// the requester's token, and Everyone is a member of every token including
// the account's own self-change bind - so a Deny on Everyone alone already
// blocks self-change, independently of whatever the SELF entry says, and
// vice versa. ADUC's "User cannot change password" checkbox always flips
// both together, but nothing in the access-check requires both to be
// present for the effect to hold, so OR is the correct - not merely
// convenient - condition. Counting groups by ObjectDN, not by ACE: an
// account carries two matching ACEs (Everyone + Self) when planted through
// the documented mechanism, and must count as one affected account, not two.
//
// NOT PROVEN, and left exactly as found: internal/providers/ldap/acl_parser.go's
// parseACE (line ~291) unconditionally discards every ACE whose type is not
// ACCESS_ALLOWED or ACCESS_ALLOWED_OBJECT - which means a DENY object ACE,
// including the one this detector now looks for, never reaches
// data.ACLEntries from a real collector run. Real plant/revert on DC01
// confirms this end-to-end (see VERDICT.md): the two Deny ACEs are planted
// and independently confirmed live in the DACL, but a real etc-collector
// audit against the same account reports Count=0 throughout, not the
// 0->1->0 this fix would otherwise demonstrate. This detector's condition
// is the correct one to evaluate once the ACE reaches DetectorData; it
// cannot itself close the gap upstream of it without touching
// internal/providers/ldap/**, which VERDICT.md explains is out of scope
// here rather than applied.
func (d *CannotChangeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	blockedDNs := make(map[string]bool, len(data.ACLEntries))

	for _, ace := range data.ACLEntries {
		if ace.ObjectType == "" || !strings.EqualFold(ace.ObjectType, types.GUIDChangePassword) {
			continue
		}
		if !strings.Contains(strings.ToUpper(ace.AceType), "DENIED") {
			continue // ACCESS_ALLOWED[_OBJECT] grants the right; it doesn't restrict it
		}
		if ace.Trustee != sidEveryone && ace.Trustee != sidSelf {
			continue
		}
		blockedDNs[strings.ToLower(ace.ObjectDN)] = true
	}

	var affected []types.User
	for _, u := range data.Users {
		if blockedDNs[strings.ToLower(u.DN)] {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "User Cannot Change Password",
		Description: "User accounts denied the User-Change-Password extended right for Everyone or " +
			"NT AUTHORITY\\SELF, preventing self-service password rotation. Detects the real AD DS " +
			"representation (Deny ACEs on the Change-Password extended right); does not depend on the " +
			"userAccountControl bit, which real AD DS never sets over LDAP.",
		Count: len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCannotChangeDetector())
}
