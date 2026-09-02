package other

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// T_023 — BADSUCCESSOR_DMSA_ESCALATION reported 288 criticals on DC01, every
// one of them a user account nested under an OU (qa verdict §2). These tests
// pin both directions: the false positive must die, the true positive must
// survive.

const (
	bsDomainDN = "DC=example,DC=com"
	bsOUDN     = "OU=IT,OU=Tokyo," + bsDomainDN
	bsUserDN   = "CN=Akira Jackson," + bsOUDN // the exact FP shape from DC01
	bsHelpdesk = "S-1-5-21-1234567890-1111111111-2222222222-1337"
	bsFullCtrl = 0x000F01FF // full control — carries CreateChild (0x1)
)

// bsData wires ACEs plus the DN-indexed cache the detector reads object
// classes from (the engine builds it in collectData).
func bsData(aces []types.ACLEntry, byDN map[string]*audit.ObjectMeta) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		ObjectByDN:     byDN,
	}
}

func bsIndex() map[string]*audit.ObjectMeta {
	return map[string]*audit.ObjectMeta{
		bsUserDN:   {DN: bsUserDN, Name: "Akira Jackson", EntityType: types.EntityTypeUser},
		bsOUDN:     {DN: bsOUDN, Name: "IT", EntityType: types.EntityTypeOU},
		bsDomainDN: {DN: bsDomainDN, Name: "example.com", EntityType: types.EntityTypeDomain},
	}
}

func bsDetect(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewBadSuccessorDMSADetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// TestBadSuccessorRequiresOUObjectClass covers acceptance §1: the detector must
// test the object CLASS, not a DN substring.
func TestBadSuccessorRequiresOUObjectClass(t *testing.T) {
	t.Run("user nested under an OU does NOT fire", func(t *testing.T) {
		// This is the DC01 false positive: full control on a USER whose DN
		// contains "OU=" because it lives under OU=IT,OU=Tokyo.
		f := bsDetect(t, bsData([]types.ACLEntry{{
			ObjectDN:   bsUserDN,
			Trustee:    bsHelpdesk,
			AccessMask: bsFullCtrl,
			AceType:    "ACCESS_ALLOWED",
		}}, bsIndex()))
		if f.Count != 0 {
			t.Fatalf("a user nested under an OU must not be reported as a dMSA container, got count=%d", f.Count)
		}
		if len(f.AffectedEntities) != 0 {
			t.Fatalf("count=0 must carry no entities, got %d", len(f.AffectedEntities))
		}
	})

	t.Run("real OU with CreateChild for a non-admin DOES fire", func(t *testing.T) {
		// The TRUE positive: a non-privileged principal can create arbitrary
		// child objects — including a dMSA — directly in an OU.
		f := bsDetect(t, bsData([]types.ACLEntry{{
			ObjectDN:   bsOUDN,
			Trustee:    bsHelpdesk,
			AccessMask: 0x1, // pure CreateChild, ObjectType empty = any class
			AceType:    "ACCESS_ALLOWED",
		}}, bsIndex()))
		if f.Count != 1 {
			t.Fatalf("CreateChild on a real OU must fire, got count=%d", f.Count)
		}
		if len(f.AffectedEntities) != 1 {
			t.Fatalf("a fired finding must be actionable, got %d entities", len(f.AffectedEntities))
		}
		if f.Severity != types.SeverityCritical {
			t.Errorf("severity = %q, want critical", f.Severity)
		}
	})

	t.Run("domain root counts as a container", func(t *testing.T) {
		f := bsDetect(t, bsData([]types.ACLEntry{{
			ObjectDN:   bsDomainDN,
			Trustee:    bsHelpdesk,
			AccessMask: bsFullCtrl,
			AceType:    "ACCESS_ALLOWED",
		}}, bsIndex()))
		if f.Count != 1 {
			t.Fatalf("CreateChild on the domain root must fire, got count=%d", f.Count)
		}
	})

	t.Run("unknown DN falls back to the leading RDN, not a substring", func(t *testing.T) {
		// Cache miss (LookupBatch failure). "OU=Orphan,…" IS an OU; the user
		// DN merely contains "OU=" and must still be rejected.
		orphanOU := "OU=Orphan," + bsDomainDN
		f := bsDetect(t, bsData([]types.ACLEntry{
			{ObjectDN: orphanOU, Trustee: bsHelpdesk, AccessMask: bsFullCtrl, AceType: "ACCESS_ALLOWED"},
			{ObjectDN: "CN=Nested," + orphanOU, Trustee: bsHelpdesk, AccessMask: bsFullCtrl, AceType: "ACCESS_ALLOWED"},
		}, nil))
		if f.Count != 1 {
			t.Fatalf("only the OU itself must fire on a cache miss, got count=%d", f.Count)
		}
	})
}

// TestBadSuccessorCountsUniqueObjects covers acceptance §1: count containers,
// not ACEs (286 unique objects were inflated to 288 findings on DC01).
func TestBadSuccessorCountsUniqueObjects(t *testing.T) {
	f := bsDetect(t, bsData([]types.ACLEntry{
		{ObjectDN: bsOUDN, Trustee: bsHelpdesk, AccessMask: bsFullCtrl, AceType: "ACCESS_ALLOWED"},
		{ObjectDN: bsOUDN, Trustee: "S-1-1-0", AccessMask: bsFullCtrl, AceType: "ACCESS_ALLOWED"}, // Everyone, same OU
	}, bsIndex()))
	if f.Count != 1 {
		t.Fatalf("two ACEs on the same OU = 1 exposed container, got count=%d", f.Count)
	}
	if len(f.AffectedEntities) != f.Count {
		t.Fatalf("count (%d) and entities (%d) must agree", f.Count, len(f.AffectedEntities))
	}
}

// TestBadSuccessorObjectTypeScope pins the remaining predicates: DENY ACEs,
// privileged trustees, and CreateChild scoped to a class that is not a dMSA.
func TestBadSuccessorObjectTypeScope(t *testing.T) {
	cases := []struct {
		name string
		ace  types.ACLEntry
		want int
	}{
		{
			name: "DENY ACE is not a grant",
			ace:  types.ACLEntry{ObjectDN: bsOUDN, Trustee: bsHelpdesk, AccessMask: bsFullCtrl, AceType: "ACCESS_DENIED"},
			want: 0,
		},
		{
			name: "privileged trustee is expected to hold it",
			ace:  types.ACLEntry{ObjectDN: bsOUDN, Trustee: "S-1-5-21-1234567890-1111111111-2222222222-512", AccessMask: bsFullCtrl, AceType: "ACCESS_ALLOWED"},
			want: 0,
		},
		{
			name: "CreateChild scoped to the computer class cannot create a dMSA",
			ace:  types.ACLEntry{ObjectDN: bsOUDN, Trustee: bsHelpdesk, AccessMask: 0x1, AceType: "ACCESS_ALLOWED", ObjectType: "bf967a86-0de6-11d0-a285-00aa003049e2"},
			want: 0,
		},
		{
			name: "CreateChild scoped to the dMSA class DOES fire",
			ace:  types.ACLEntry{ObjectDN: bsOUDN, Trustee: bsHelpdesk, AccessMask: 0x1, AceType: "ACCESS_ALLOWED", ObjectType: "0FEB936F-47B3-49F2-9386-1DEDC2C23765"},
			want: 1,
		},
		{
			name: "GenericAll subsumes CreateChild",
			ace:  types.ACLEntry{ObjectDN: bsOUDN, Trustee: bsHelpdesk, AccessMask: 0x10000000, AceType: "ACCESS_ALLOWED"},
			want: 1,
		},
		{
			name: "a mask without any create right does not fire",
			ace:  types.ACLEntry{ObjectDN: bsOUDN, Trustee: bsHelpdesk, AccessMask: 0x10, AceType: "ACCESS_ALLOWED"}, // READ_PROP
			want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := bsDetect(t, bsData([]types.ACLEntry{tc.ace}, bsIndex()))
			if f.Count != tc.want {
				t.Fatalf("count = %d, want %d", f.Count, tc.want)
			}
		})
	}
}
