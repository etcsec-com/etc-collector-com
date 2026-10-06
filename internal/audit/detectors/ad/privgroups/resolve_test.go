package privgroups

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestDNsBySIDSuffix_MatchesSuffix pins the baseline positive: a collected
// group whose SID ends in a requested suffix is returned, DN lowercased.
func TestDNsBySIDSuffix_MatchesSuffix(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	data := &audit.DetectorData{
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
		},
	}

	dns := DNsBySIDSuffix(data, []string{"-512"})
	if !dns["cn=domain admins,cn=users,dc=example,dc=com"] {
		t.Fatalf("dns = %+v, want the group DN present, lowercased", dns)
	}
	if len(dns) != 1 {
		t.Fatalf("len(dns) = %d, want 1", len(dns))
	}
}

// TestDNsBySIDSuffix_OrdinaryRIDExcluded is the leurre case at the
// resolver level: a group whose SID does NOT end in any requested suffix
// (an ordinary domain RID) must not appear in the result, regardless of
// its CN.
func TestDNsBySIDSuffix_OrdinaryRIDExcluded(t *testing.T) {
	dn := "CN=Backup Operators,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-97001" // ordinary RID, not -551
	data := &audit.DetectorData{
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
		},
	}

	dns := DNsBySIDSuffix(data, []string{"-551"})
	if len(dns) != 0 {
		t.Fatalf("dns = %+v, want empty (ordinary RID must not match -551)", dns)
	}
}

// TestDNsBySIDSuffix_NonGroupEntityExcluded proves the EntityType guard: an
// ObjectBySID entry whose SID matches a requested suffix but whose
// EntityType is NOT "group" (e.g. a user whose SID happens to share the
// suffix pattern) must never be resolved as a privileged group DN.
func TestDNsBySIDSuffix_NonGroupEntityExcluded(t *testing.T) {
	dn := "CN=Some User,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	data := &audit.DetectorData{
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeUser},
		},
	}

	dns := DNsBySIDSuffix(data, []string{"-512"})
	if len(dns) != 0 {
		t.Fatalf("dns = %+v, want empty (a non-group entity must never be resolved as a privileged group)", dns)
	}
}

// TestDNsBySIDSuffix_NilMetaSkipped proves a nil map entry doesn't panic
// and is simply skipped.
func TestDNsBySIDSuffix_NilMetaSkipped(t *testing.T) {
	data := &audit.DetectorData{
		ObjectBySID: map[string]*audit.ObjectMeta{
			"S-1-5-21-1111111111-2222222222-3333333333-512": nil,
		},
	}

	dns := DNsBySIDSuffix(data, []string{"-512"})
	if len(dns) != 0 {
		t.Fatalf("dns = %+v, want empty (nil meta must be skipped, not panic)", dns)
	}
}

// TestDNsBySIDSuffix_NeighboringRIDNotConfusedWithShorterSuffix proves the
// match is exact-length (strings.HasSuffix), not substring
// (strings.Contains): a group whose SID ends in "-5120" must NOT be
// returned for a "-512" request, while a real "-512" group still is.
// HasSuffix("...-5120", "-512") is false; Contains("...-5120", "-512")
// would be true and would misread this ordinary RID as Domain Admins.
func TestDNsBySIDSuffix_NeighboringRIDNotConfusedWithShorterSuffix(t *testing.T) {
	neighborDN := "CN=Ordinary Group 5120,CN=Users,DC=example,DC=com"
	neighborSID := "S-1-5-21-1111111111-2222222222-3333333333-5120"
	realDN := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	realSID := "S-1-5-21-1111111111-2222222222-3333333333-512"
	data := &audit.DetectorData{
		ObjectBySID: map[string]*audit.ObjectMeta{
			neighborSID: {DN: neighborDN, SID: neighborSID, EntityType: types.EntityTypeGroup},
			realSID:     {DN: realDN, SID: realSID, EntityType: types.EntityTypeGroup},
		},
	}

	dns := DNsBySIDSuffix(data, []string{"-512"})
	if dns["cn=ordinary group 5120,cn=users,dc=example,dc=com"] {
		t.Fatalf("dns = %+v, want the -5120 group absent (a neighboring RID must not match suffix -512)", dns)
	}
	if !dns["cn=domain admins,cn=users,dc=example,dc=com"] {
		t.Fatalf("dns = %+v, want the real -512 group present", dns)
	}
	if len(dns) != 1 {
		t.Fatalf("len(dns) = %d, want 1 (only the real -512 group must match)", len(dns))
	}
}

// TestIsMemberOfAny_DirectMatch pins the baseline positive: a DN present in
// memberOf that is also a key of dns is found.
func TestIsMemberOfAny_DirectMatch(t *testing.T) {
	dns := map[string]bool{"cn=domain admins,cn=users,dc=example,dc=com": true}
	memberOf := []string{"CN=Domain Admins,CN=Users,DC=example,DC=com"}

	if !IsMemberOfAny(memberOf, dns) {
		t.Fatalf("IsMemberOfAny = false, want true (exact DN present, case aside)")
	}
}

// TestIsMemberOfAny_CaseInsensitive proves the match tolerates case
// differences on BOTH sides (the memberOf DN as collected from LDAP, and
// the dns map built by DNsBySIDSuffix, are not guaranteed to share casing).
func TestIsMemberOfAny_CaseInsensitive(t *testing.T) {
	dns := map[string]bool{"cn=backup operators,cn=builtin,dc=example,dc=com": true}
	memberOf := []string{"cn=BACKUP OPERATORS,CN=Builtin,dc=EXAMPLE,dc=com"}

	if !IsMemberOfAny(memberOf, dns) {
		t.Fatalf("IsMemberOfAny = false, want true (case must not defeat the match)")
	}
}

// TestIsMemberOfAny_NoMatch is the negative case: a memberOf DN absent from
// dns must not be reported as a match.
func TestIsMemberOfAny_NoMatch(t *testing.T) {
	dns := map[string]bool{"cn=domain admins,cn=users,dc=example,dc=com": true}
	memberOf := []string{"CN=Marketing,OU=Groups,DC=example,DC=com"}

	if IsMemberOfAny(memberOf, dns) {
		t.Fatalf("IsMemberOfAny = true, want false (this DN is not in dns)")
	}
}

// TestIsMemberOfAny_EmptyMemberOf pins the edge case: an empty memberOf
// slice can never match, regardless of dns content.
func TestIsMemberOfAny_EmptyMemberOf(t *testing.T) {
	dns := map[string]bool{"cn=domain admins,cn=users,dc=example,dc=com": true}

	if IsMemberOfAny(nil, dns) {
		t.Fatalf("IsMemberOfAny = true, want false (empty memberOf)")
	}
}
