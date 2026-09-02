package adcs

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	esc4DomainDN  = "DC=example,DC=com"
	esc4DomainSID = "S-1-5-21-1234567890-1111111111-2222222222"
	esc4Attacker  = esc4DomainSID + "-93801"
	esc4ConfigDN  = "CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com"
)

// TestESC4_EntityOrderIsDeterministic covers T_046/B_048: affectedTemplates
// is a map keyed by template DN, so ranging it directly to build entities
// would give a randomized order per process. With several vulnerable
// templates, an unsorted range would very rarely land in DN order by chance
// across repeated calls — asserting the exact expected order pins the sort.
func TestESC4_EntityOrderIsDeterministic(t *testing.T) {
	names := []string{"Zeta", "Alpha", "Mike", "Bravo"}
	var templates []types.CertTemplate
	var aces []types.ACLEntry
	for _, n := range names {
		dn := "CN=" + n + "," + esc4ConfigDN
		templates = append(templates, types.CertTemplate{DN: dn, Name: n})
		aces = append(aces, types.ACLEntry{
			ObjectDN: dn, Trustee: esc4Attacker, AccessMask: GenericAll, AceType: "ACCESS_ALLOWED",
		})
	}

	want := []string{"CN=Alpha," + esc4ConfigDN, "CN=Bravo," + esc4ConfigDN, "CN=Mike," + esc4ConfigDN, "CN=Zeta," + esc4ConfigDN}

	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: esc4DomainDN, DomainSID: esc4DomainSID},
		CertTemplates:  templates,
		ACLEntries:     aces,
	}

	for i := 0; i < 5; i++ {
		findings := NewESC4Detector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("run %d: expected exactly 1 finding, got %d", i, len(findings))
		}
		ents := findings[0].AffectedEntities
		if len(ents) != len(want) {
			t.Fatalf("run %d: expected %d entities, got %d", i, len(want), len(ents))
		}
		for j, ent := range ents {
			if ent.DN != want[j] {
				t.Fatalf("run %d: entity order not deterministic — position %d = %q, want %q", i, j, ent.DN, want[j])
			}
		}
	}
}
