package replication

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestDuplicateSpn_EntityOrderIsDeterministic exists because spnMap is a
// map keyed by SPN, so ranging it directly to find duplicate groups would
// give a randomized order per process. With several duplicated SPNs, an
// unsorted range would very rarely land in SPN order by chance across
// repeated calls - asserting the exact expected order pins the sort.
func TestDuplicateSpn_EntityOrderIsDeterministic(t *testing.T) {
	const domainDN = "DC=example,DC=com"
	// Each SPN below is shared by exactly two users, so every DN is unique
	// across groups and the final entity order is fully determined by the
	// SPN sort order.
	users := []types.User{
		{DN: "CN=zulu-a," + domainDN, ServicePrincipalNames: []string{"HOST/zulu.example.com"}},
		{DN: "CN=zulu-b," + domainDN, ServicePrincipalNames: []string{"HOST/zulu.example.com"}},
		{DN: "CN=alpha-a," + domainDN, ServicePrincipalNames: []string{"HOST/alpha.example.com"}},
		{DN: "CN=alpha-b," + domainDN, ServicePrincipalNames: []string{"HOST/alpha.example.com"}},
		{DN: "CN=mike-a," + domainDN, ServicePrincipalNames: []string{"HOST/mike.example.com"}},
		{DN: "CN=mike-b," + domainDN, ServicePrincipalNames: []string{"HOST/mike.example.com"}},
	}

	want := []string{
		"CN=alpha-a," + domainDN, "CN=alpha-b," + domainDN,
		"CN=mike-a," + domainDN, "CN=mike-b," + domainDN,
		"CN=zulu-a," + domainDN, "CN=zulu-b," + domainDN,
	}

	data := &audit.DetectorData{IncludeDetails: true, Users: users}

	for i := 0; i < 5; i++ {
		findings := NewDuplicateSpnDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("run %d: expected exactly 1 finding, got %d", i, len(findings))
		}
		ents := findings[0].AffectedEntities
		if len(ents) != len(want) {
			t.Fatalf("run %d: expected %d entities, got %d (%v)", i, len(want), len(ents), ents)
		}
		for j, ent := range ents {
			if ent.DN != want[j] {
				t.Fatalf("run %d: entity order not deterministic - position %d = %q, want %q", i, j, ent.DN, want[j])
			}
		}
	}
}

// TestDuplicateSpn_CaseInsensitiveComparison covers the case where two
// accounts register the "same" SPN differing only by letter case (e.g.
// "HOST/Server1" vs "host/server1"). Per Microsoft Learn's setspn
// documentation ("SPNs aren't case sensitive when used by Microsoft
// Windows-based computers"), Windows/Kerberos treats these as the same
// registration, so DUPLICATE_SPN must flag them as duplicates. Against the
// pre-fix code (an exact-match map keyed on the raw SPN string) this pair
// would never collide and Count would be 0 - this test fails there and
// passes once the comparison is case-folded.
func TestDuplicateSpn_CaseInsensitiveComparison(t *testing.T) {
	users := []types.User{
		{DN: "CN=svc-a,DC=example,DC=com", ServicePrincipalNames: []string{"HOST/Server1.example.com"}},
		{DN: "CN=svc-b,DC=example,DC=com", ServicePrincipalNames: []string{"host/server1.example.com"}},
	}
	data := &audit.DetectorData{IncludeDetails: true, Users: users}

	findings := NewDuplicateSpnDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]

	if f.Count != 2 {
		t.Fatalf("expected Count=2 (both accounts holding the case-variant duplicate SPN), got %d", f.Count)
	}
	if len(f.AffectedEntities) != 2 {
		t.Fatalf("expected both accounts flagged, got %+v", f.AffectedEntities)
	}

	// The description must clarify what Count actually measures (accounts
	// holding a duplicated SPN, not the number of distinct duplicated SPNs)
	// since a single duplicated SPN shared by two accounts yields Count=2.
	descLower := strings.ToLower(f.Description)
	if !strings.Contains(descLower, "count is the number of accounts") {
		t.Fatalf("description does not clarify Count semantics: %q", f.Description)
	}
}
