package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// EveryoneInPrivilegedDetector checks for Everyone group in privileged groups
type EveryoneInPrivilegedDetector struct {
	audit.BaseDetector
}

// NewEveryoneInPrivilegedDetector creates a new detector
func NewEveryoneInPrivilegedDetector() *EveryoneInPrivilegedDetector {
	return &EveryoneInPrivilegedDetector{
		BaseDetector: audit.NewBaseDetector("GROUP_EVERYONE_IN_PRIVILEGED", audit.CategoryGroups),
	}
}

// everyoneInPrivilegedSIDSuffixes are the same 8 built-in privileged groups
// the previous name-based list covered, matched by SID instead: a localized
// DC ("Administrateurs", "Opérateurs de sauvegarde") or a renamed/homonym
// group defeats a name match but not a SID match. Domain Admins (-512),
// Schema Admins (-518) and Enterprise Admins (-519) are domain-relative
// RIDs; the other five are fixed, forest-wide well-known SIDs for the
// builtin container (internal/audit/wellknown_sids.go). Kept to exactly
// these 8 on explicit ticket instruction: extending coverage to Domain
// Controllers, Key Admins or Anonymous Logon is a product scope decision,
// not something this bug fix makes on its own.
var everyoneInPrivilegedSIDSuffixes = []string{
	"-512",         // Domain Admins
	"-518",         // Schema Admins
	"-519",         // Enterprise Admins
	"S-1-5-32-544", // Administrators
	"S-1-5-32-548", // Account Operators
	"S-1-5-32-549", // Server Operators
	"S-1-5-32-550", // Print Operators
	"S-1-5-32-551", // Backup Operators
}

// isEveryoneForeignSecurityPrincipal reports whether memberDN is the
// Everyone (S-1-1-0) foreign security principal: an exact DN prefix match on
// its CN inside the ForeignSecurityPrincipals container, not a substring
// test against "everyone" or "world" anywhere in the DN. A member merely
// named or organized that way (e.g. an admin under OU=Worldwide, or a user
// CN=Everyone Test) does NOT satisfy this exact-prefix check - unlike the
// old code's bare Contains("everyone")/Contains("world"), which flagged
// exactly this class of member as a false positive. The FSP container name
// itself is a fixed well-known object name: AD's wellKnownObjects attribute
// binds a per-forest-invariant GUID to "CN=ForeignSecurityPrincipals,<domain>"
// regardless of the DC's installation language, so the literal CN never
// varies across forests.
func isEveryoneForeignSecurityPrincipal(memberDN string) bool {
	return strings.HasPrefix(strings.ToLower(memberDN), "cn=s-1-1-0,cn=foreignsecurityprincipals,")
}

// Detect executes the detection. Scope: direct membership only - a group
// nested inside one of the 8 privileged groups that itself carries Everyone
// is not resolved transitively; only a direct member of one of the 8 is
// considered.
func (d *EveryoneInPrivilegedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group

	privilegedDNs := privgroups.DNsBySIDSuffix(data, everyoneInPrivilegedSIDSuffixes)

	for _, group := range data.Groups {
		if !privilegedDNs[strings.ToLower(group.DN)] || len(group.Member) == 0 {
			continue
		}

		for _, member := range group.Member {
			if isEveryoneForeignSecurityPrincipal(member) {
				affected = append(affected, group)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Everyone in Privileged Group",
		Description: "The Everyone principal is a member of a privileged group. This grants ALL users (including anonymous) administrative privileges.",
		Count:       len(affected),
		Details: map[string]interface{}{
			"recommendation": "Immediately remove Everyone from privileged groups.",
			"risk":           "Complete domain compromise - anyone can authenticate as admin.",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewEveryoneInPrivilegedDetector())
}
