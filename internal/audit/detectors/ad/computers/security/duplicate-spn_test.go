package security

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestDuplicateSpn_EntityOrderIsDeterministic covers T_046/B_048:
// duplicateComputers is a map keyed by DN, so ranging it directly to build
// the affected slice would give a randomized order per process. With several
// duplicated computers, an unsorted range would very rarely land in DN order
// by chance across repeated calls — asserting the exact expected order pins
// the sort.
func TestDuplicateSpn_EntityOrderIsDeterministic(t *testing.T) {
	const domainDN = "DC=example,DC=com"
	names := []string{"WKS-ZULU", "WKS-ALPHA", "WKS-MIKE", "WKS-BRAVO"}
	spn := "HOST/shared-spn.example.com"

	var computers []types.Computer
	for _, n := range names {
		computers = append(computers, types.Computer{
			DN:                    "CN=" + n + ",OU=Computers," + domainDN,
			SAMAccountName:        n + "$",
			ServicePrincipalNames: []string{spn},
		})
	}

	want := []string{
		"CN=WKS-ALPHA,OU=Computers," + domainDN,
		"CN=WKS-BRAVO,OU=Computers," + domainDN,
		"CN=WKS-MIKE,OU=Computers," + domainDN,
		"CN=WKS-ZULU,OU=Computers," + domainDN,
	}

	data := &audit.DetectorData{IncludeDetails: true, Computers: computers}

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
