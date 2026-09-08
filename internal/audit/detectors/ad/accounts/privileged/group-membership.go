package privileged

import (
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// MemberKind classifies one real (LDAP member/Member attribute) group
// member by the kind of AD object it points at.
type MemberKind string

const (
	MemberKindUser                     MemberKind = "user"
	MemberKindGroup                    MemberKind = "group"
	MemberKindComputer                 MemberKind = "computer"
	MemberKindForeignSecurityPrincipal MemberKind = "foreignSecurityPrincipal"
	MemberKindUnknown                  MemberKind = "unknown"
)

// wellKnownFSPNames labels the universally-scoped well-known SIDs worth
// calling out by name when found as a foreignSecurityPrincipal member of a
// privileged builtin group - each one silently grants the privilege to every
// authenticated user, everyone, or anonymous connections, not to one person.
var wellKnownFSPNames = map[string]string{
	"S-1-1-0":  "Everyone",
	"S-1-5-11": "Authenticated Users",
	"S-1-5-7":  "Anonymous Logon",
}

// ClassifiedMember is one real member of a builtin group, resolved from the
// group's own Members/Member LDAP attribute (ground truth) instead of
// data.Users[].MemberOf, which only ever surfaces direct user members and
// stays silent about nested groups, computers, and foreignSecurityPrincipal
// members.
type ClassifiedMember struct {
	Kind   MemberKind
	Entity types.AffectedEntity
	// SID and WellKnownName are populated only when Kind ==
	// MemberKindForeignSecurityPrincipal.
	SID           string
	WellKnownName string
}

// FindBuiltinGroup locates a builtin group by CN or sAMAccountName
// (case-insensitive) among the collected groups.
func FindBuiltinGroup(groups []types.Group, name string) *types.Group {
	for i := range groups {
		g := &groups[i]
		if strings.EqualFold(g.CN, name) || strings.EqualFold(g.SAMAccountName, name) {
			return g
		}
	}
	return nil
}

// isForeignSecurityPrincipalDN reports whether dn sits under the domain's
// CN=ForeignSecurityPrincipals container.
func isForeignSecurityPrincipalDN(dn string) bool {
	return strings.Contains(strings.ToLower(dn), "cn=foreignsecurityprincipals,")
}

// fspSID extracts the SID from a foreignSecurityPrincipal DN, whose leading
// RDN is the SID itself, e.g.
// "CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=corp,DC=local" -> "S-1-5-11".
func fspSID(dn string) string {
	rdn := dn
	if idx := strings.Index(dn, ","); idx != -1 {
		rdn = dn[:idx]
	}
	rdn = strings.TrimSpace(rdn)
	if len(rdn) > 3 && strings.EqualFold(rdn[:3], "cn=") {
		return rdn[3:]
	}
	return rdn
}

// ResolveRealMembers classifies every real member of group (its LDAP
// Members/Member attribute) into user / nested group / computer /
// foreignSecurityPrincipal, cross-referencing the collected Users, Groups
// and Computers by DN.
//
// This is deliberately distinct from a data.Users[].MemberOf scan: MemberOf
// only ever lists direct user members and says nothing about nested groups,
// computer members, or foreignSecurityPrincipal members. Server
// Operators on the lab DC has S-1-5-11 (Authenticated Users) as its only
// member, and Backup Operators has S-1-1-0 (Everyone); the old MemberOf scan
// found no matching user and stayed completely silent on both, even though
// every authenticated user effectively holds the privilege.
func ResolveRealMembers(data *audit.DetectorData, group *types.Group) []ClassifiedMember {
	members := group.Members
	if len(members) == 0 {
		members = group.Member
	}
	if len(members) == 0 {
		return nil
	}

	usersByDN := make(map[string]*types.User, len(data.Users))
	for i := range data.Users {
		usersByDN[strings.ToLower(data.Users[i].DN)] = &data.Users[i]
	}
	groupsByDN := make(map[string]*types.Group, len(data.Groups))
	for i := range data.Groups {
		groupsByDN[strings.ToLower(data.Groups[i].DN)] = &data.Groups[i]
	}
	computersByDN := make(map[string]*types.Computer, len(data.Computers))
	for i := range data.Computers {
		computersByDN[strings.ToLower(data.Computers[i].DN)] = &data.Computers[i]
	}

	result := make([]ClassifiedMember, 0, len(members))
	for _, dn := range members {
		lower := strings.ToLower(dn)

		if isForeignSecurityPrincipalDN(dn) {
			sid := fspSID(dn)
			name := wellKnownFSPNames[sid]
			entity := types.AffectedEntity{
				Type: string(MemberKindForeignSecurityPrincipal),
				DN:   dn,
				SID:  sid,
			}
			if name != "" {
				entity.Name = name
			}
			result = append(result, ClassifiedMember{
				Kind:          MemberKindForeignSecurityPrincipal,
				Entity:        entity,
				SID:           sid,
				WellKnownName: name,
			})
			continue
		}

		if u, ok := usersByDN[lower]; ok {
			result = append(result, ClassifiedMember{Kind: MemberKindUser, Entity: types.UserToAffectedEntity(u)})
			continue
		}
		if g, ok := groupsByDN[lower]; ok {
			result = append(result, ClassifiedMember{Kind: MemberKindGroup, Entity: types.GroupToAffectedEntity(g)})
			continue
		}
		if c, ok := computersByDN[lower]; ok {
			result = append(result, ClassifiedMember{Kind: MemberKindComputer, Entity: types.ComputerToAffectedEntity(c)})
			continue
		}

		// Member DN isn't in any collected collection (out-of-scope object,
		// or a principal type we don't track) - still report it rather than
		// silently dropping a real member.
		result = append(result, ClassifiedMember{
			Kind:   MemberKindUnknown,
			Entity: types.AffectedEntity{Type: string(MemberKindUnknown), DN: dn},
		})
	}
	return result
}
