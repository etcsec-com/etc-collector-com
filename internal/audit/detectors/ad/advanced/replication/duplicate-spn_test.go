package replication

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestDuplicateSpn_EntityOrderIsDeterministic covers T_046/B_048: spnMap is a
// map keyed by SPN, so ranging it directly to find duplicate groups would
// give a randomized order per process. With several duplicated SPNs, an
// unsorted range would very rarely land in SPN order by chance across
// repeated calls — asserting the exact expected order pins the sort.
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
				t.Fatalf("run %d: entity order not deterministic — position %d = %q, want %q", i, j, ent.DN, want[j])
			}
		}
	}
}
