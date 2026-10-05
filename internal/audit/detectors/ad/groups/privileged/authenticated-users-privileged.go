package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AuthenticatedUsersPrivilegedDetector checks for Authenticated Users in privileged groups
type AuthenticatedUsersPrivilegedDetector struct {
	audit.BaseDetector
}

// NewAuthenticatedUsersPrivilegedDetector creates a new detector
func NewAuthenticatedUsersPrivilegedDetector() *AuthenticatedUsersPrivilegedDetector {
	return &AuthenticatedUsersPrivilegedDetector{
		BaseDetector: audit.NewBaseDetector("GROUP_AUTHENTICATED_USERS_PRIVILEGED", audit.CategoryGroups),
	}
}

// authenticatedUsersPrivilegedSIDSuffixes are the same 7 built-in privileged
// groups the previous name-based list covered, matched by SID instead: a
// localized DC ("Administrateurs", "Opérateurs de sauvegarde") or a
// renamed/homonym group defeats a name match but not a SID match. Domain
// Admins (-512), Schema Admins (-518) and Enterprise Admins (-519) are
// domain-relative RIDs; the other four are fixed, forest-wide well-known
// SIDs for the builtin container (internal/audit/wellknown_sids.go). Print
// Operators (S-1-5-32-550) is deliberately absent, same as the original
// 7-name list: adding it is a product scope decision, not something this
// bug fix makes on its own.
var authenticatedUsersPrivilegedSIDSuffixes = []string{
	"-512",         // Domain Admins
	"-518",         // Schema Admins
	"-519",         // Enterprise Admins
	"S-1-5-32-544", // Administrators
	"S-1-5-32-548", // Account Operators
	"S-1-5-32-549", // Server Operators
	"S-1-5-32-551", // Backup Operators
}

// isAuthenticatedUsersForeignSecurityPrincipal reports whether memberDN is
// the Authenticated Users (S-1-5-11) foreign security principal: an exact DN
// prefix match on its CN inside the ForeignSecurityPrincipals container, not
// a substring test against "authenticated users", "utilisateurs
// authentifiés" or "S-1-5-11" anywhere in the DN. The old bare
// Contains(member, "S-1-5-11") also matched S-1-5-113 (Local account) and
// S-1-5-114 (Local account and member of Administrators group), two
// unrelated well-known SIDs that merely share this SID as a textual prefix.
// The FSP container name itself is a fixed well-known object name: AD's
// wellKnownObjects attribute binds a per-forest-invariant GUID to
// "CN=ForeignSecurityPrincipals,<domain>" regardless of the DC's
// installation language, so the literal CN never varies across forests.
func isAuthenticatedUsersForeignSecurityPrincipal(memberDN string) bool {
	return strings.HasPrefix(strings.ToLower(memberDN), "cn=s-1-5-11,cn=foreignsecurityprincipals,")
}

// Detect executes the detection. Scope: direct membership only - a group
// nested inside one of the 7 privileged groups that itself carries
// Authenticated Users is not resolved transitively; only a direct member of
// one of the 7 is considered.
func (d *AuthenticatedUsersPrivilegedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group

	privilegedDNs := privgroups.DNsBySIDSuffix(data, authenticatedUsersPrivilegedSIDSuffixes)

	for _, group := range data.Groups {
		if !privilegedDNs[strings.ToLower(group.DN)] || len(group.Member) == 0 {
			continue
		}

		for _, member := range group.Member {
			if isAuthenticatedUsersForeignSecurityPrincipal(member) {
				affected = append(affected, group)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Authenticated Users in Privileged Group",
		Description: "Authenticated Users principal is a member of a privileged group. This grants ALL authenticated domain users administrative privileges.",
		Count:       len(affected),
		Details: map[string]interface{}{
			"recommendation": "Remove Authenticated Users from privileged groups immediately.",
			"risk":           "Any domain user can perform administrative actions.",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAuthenticatedUsersPrivilegedDetector())
}
