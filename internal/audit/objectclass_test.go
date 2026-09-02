package audit

import (
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestObjectClassToEntityType(t *testing.T) {
	cases := []struct {
		name    string
		classes []string
		want    string
	}{
		{"user chain", []string{"top", "person", "organizationalPerson", "user"}, types.EntityTypeUser},
		{"computer chain", []string{"top", "person", "organizationalPerson", "user", "computer"}, types.EntityTypeComputer},
		{"group", []string{"top", "group"}, types.EntityTypeGroup},
		{"OU", []string{"top", "organizationalUnit"}, types.EntityTypeOU},
		{"GPO", []string{"top", "container", "groupPolicyContainer"}, types.EntityTypeGPO},
		{"cert template", []string{"top", "pKICertificateTemplate"}, types.EntityTypeCertTemplate},
		{"DNS zone", []string{"top", "dnsZone"}, types.EntityTypeDNSZone},
		{"DNS node", []string{"top", "dnsNode"}, types.EntityTypeDNSZone},
		{"domain", []string{"top", "domain", "domainDNS"}, types.EntityTypeDomain},
		{"site", []string{"top", "site"}, types.EntityTypeSite},
		{"foreign security principal", []string{"top", "foreignSecurityPrincipal"}, types.EntityTypePrincipal},
		{"empty fallback", []string{}, types.EntityTypePrincipal},
		{"unknown chain fallback", []string{"top", "container", "rpcContainer"}, types.EntityTypePrincipal},
		{"case-insensitive", []string{"USER"}, types.EntityTypeUser},
		{"computer-then-user order", []string{"computer", "user"}, types.EntityTypeComputer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ObjectClassToEntityType(tc.classes); got != tc.want {
				t.Errorf("ObjectClassToEntityType(%v) = %q, want %q", tc.classes, got, tc.want)
			}
		})
	}
}
