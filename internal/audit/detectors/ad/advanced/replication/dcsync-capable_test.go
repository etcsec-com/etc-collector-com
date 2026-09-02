package replication

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// T_024 / DET_10 — DCSYNC_CAPABLE did try to skip DENY ACEs, but compared
// AceType to the literal "deny" while acl_parser.go emits ACCESS_DENIED /
// ACCESS_DENIED_OBJECT. The guard was dead code: a DENY DCSync ace counted as
// a grant.

const (
	dsDomainDN  = "DC=example,DC=com"
	dsDomainSID = "S-1-5-21-1234567890-1111111111-2222222222"
	dsAttacker  = dsDomainSID + "-93801"
)

func dsData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		DomainInfo:     &types.DomainInfo{DomainDN: dsDomainDN, DomainSID: dsDomainSID},
	}
}

// bothRights returns the pair of ACEs a DCSync-capable principal needs.
func bothRights(trustee, aceType string) []types.ACLEntry {
	return []types.ACLEntry{
		{ObjectDN: dsDomainDN, Trustee: trustee, ObjectType: DSReplicationGetChanges, AccessMask: 0x100, AceType: aceType},
		{ObjectDN: dsDomainDN, Trustee: trustee, ObjectType: DSReplicationGetChangesAll, AccessMask: 0x100, AceType: aceType},
	}
}

func dsDetect(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewDcsyncCapableDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

func TestDCSyncCapable_DenyACEsAreNotGrants(t *testing.T) {
	t.Run("DENY replication rights do NOT fire", func(t *testing.T) {
		f := dsDetect(t, dsData(bothRights(dsAttacker, "ACCESS_DENIED_OBJECT")...))
		if f.Count != 0 {
			t.Fatalf("a DENY ace grants no DCSync capability, got count=%d", f.Count)
		}
	})

	t.Run("ALLOW replication rights DO fire", func(t *testing.T) {
		f := dsDetect(t, dsData(bothRights(dsAttacker, "ACCESS_ALLOWED_OBJECT")...))
		if f.Count != 1 {
			t.Fatalf("a domain principal with both replication rights must fire, got count=%d", f.Count)
		}
		if len(f.AffectedEntities) != 1 {
			t.Fatalf("finding must be actionable, got %d entities", len(f.AffectedEntities))
		}
	})

	t.Run("Domain Admins still skipped", func(t *testing.T) {
		f := dsDetect(t, dsData(bothRights(dsDomainSID+"-512", "ACCESS_ALLOWED_OBJECT")...))
		if f.Count != 0 {
			t.Fatalf("Domain Admins holding DCSync is expected, got count=%d", f.Count)
		}
	})

	t.Run("only one of the two rights does NOT fire", func(t *testing.T) {
		f := dsDetect(t, dsData(types.ACLEntry{
			ObjectDN: dsDomainDN, Trustee: dsAttacker,
			ObjectType: DSReplicationGetChanges, AccessMask: 0x100, AceType: "ACCESS_ALLOWED_OBJECT",
		}))
		if f.Count != 0 {
			t.Fatalf("DCSync needs BOTH replication rights, got count=%d", f.Count)
		}
	})
}

// TestDCSyncCapable_EntityOrderIsDeterministic covers T_046/B_048: trustees
// are collected in a map (dcsyncTrustees) before entities are built, so
// ranging it directly would give a randomized order per process. With
// several trustees, an unsorted range would very rarely land in SID order by
// chance across repeated calls — asserting the exact expected order pins the
// sort.
func TestDCSyncCapable_EntityOrderIsDeterministic(t *testing.T) {
	trustees := []string{
		dsDomainSID + "-93801",
		dsDomainSID + "-10001",
		dsDomainSID + "-77777",
		dsDomainSID + "-20002",
	}
	var aces []types.ACLEntry
	for _, tr := range trustees {
		aces = append(aces, bothRights(tr, "ACCESS_ALLOWED_OBJECT")...)
	}

	want := []string{
		dsDomainSID + "-10001",
		dsDomainSID + "-20002",
		dsDomainSID + "-77777",
		dsDomainSID + "-93801",
	}

	for i := 0; i < 5; i++ {
		f := dsDetect(t, dsData(aces...))
		if len(f.AffectedEntities) != len(want) {
			t.Fatalf("run %d: expected %d entities, got %d", i, len(want), len(f.AffectedEntities))
		}
		for j, ent := range f.AffectedEntities {
			if ent.SID != want[j] {
				t.Fatalf("run %d: entity order not deterministic — position %d = %q, want %q (full: %v)",
					i, j, ent.SID, want[j], f.AffectedEntities)
			}
		}
	}
}
