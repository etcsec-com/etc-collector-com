package audit

import (
	"strings"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// objectClassPriority lists LDAP objectClass values in most-specific-first
// order. LDAP returns the full inheritance chain (e.g. ["top","person",
// "organizationalPerson","user","computer"]), so iterating in LDAP order
// would mis-classify a computer as a user. Instead we walk this priority
// list and return the first class that's present in the chain.
var objectClassPriority = []struct {
	cls  string
	kind string
}{
	{"computer", types.EntityTypeComputer},
	{"grouppolicycontainer", types.EntityTypeGPO},
	{"pkicertificatetemplate", types.EntityTypeCertTemplate},
	{"organizationalunit", types.EntityTypeOU},
	{"dnszone", types.EntityTypeDNSZone},
	{"dnsnode", types.EntityTypeDNSZone},
	{"domaindns", types.EntityTypeDomain},
	{"site", types.EntityTypeSite},
	{"foreignsecurityprincipal", types.EntityTypePrincipal},
	{"group", types.EntityTypeGroup},
	{"user", types.EntityTypeUser},
}

// ObjectClassToEntityType maps an LDAP objectClass attribute to a single
// canonical AffectedEntity.Type string. Returns EntityTypePrincipal as a
// fallback so unmatched objects don't silently regress to "object" again.
func ObjectClassToEntityType(classes []string) string {
	if len(classes) == 0 {
		return types.EntityTypePrincipal
	}
	have := make(map[string]struct{}, len(classes))
	for _, c := range classes {
		have[strings.ToLower(c)] = struct{}{}
	}
	for _, p := range objectClassPriority {
		if _, ok := have[p.cls]; ok {
			return p.kind
		}
	}
	return types.EntityTypePrincipal
}
