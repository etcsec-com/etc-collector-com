package gpo

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	dpDomainDN  = "DC=example,DC=com"
	dpDomainSID = "S-1-5-21-1234567890-1111111111-2222222222"
	dpAttacker  = dpDomainSID + "-93801"
)

// TestDangerousPermissions_EntityOrderIsDeterministic covers T_046/B_048:
// affectedGPOs is a map keyed by GPO DN, so ranging it directly to build
// entities would give a randomized order per process. With several affected
// GPOs, an unsorted range would very rarely land in DN order by chance
// across repeated calls — asserting the exact expected order pins the sort.
func TestDangerousPermissions_EntityOrderIsDeterministic(t *testing.T) {
	names := []string{"Zeta Policy", "Alpha Policy", "Mike Policy", "Bravo Policy"}
	var gpos []types.GPO
	var acls []audit.GPOAcl
	for _, n := range names {
		dn := "CN={" + n + "},CN=Policies,CN=System," + dpDomainDN
		gpos = append(gpos, types.GPO{DN: dn, DisplayName: n})
		acls = append(acls, audit.GPOAcl{
			GPODN: dn, Trustee: dpAttacker, TrusteeSID: dpAttacker,
			AccessMask: GenericAll, AceType: "ACCESS_ALLOWED",
		})
	}

	want := []string{
		"CN={Alpha Policy},CN=Policies,CN=System," + dpDomainDN,
		"CN={Bravo Policy},CN=Policies,CN=System," + dpDomainDN,
		"CN={Mike Policy},CN=Policies,CN=System," + dpDomainDN,
		"CN={Zeta Policy},CN=Policies,CN=System," + dpDomainDN,
	}

	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: dpDomainDN, DomainSID: dpDomainSID},
		GPOs:           gpos,
		GPOAcls:        acls,
	}

	for i := 0; i < 5; i++ {
		findings := NewDangerousPermissionsDetector().Detect(context.Background(), data)
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
