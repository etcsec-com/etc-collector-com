package moderate

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// No ACE combining WriteProperty with the "member" attribute GUID has ever
// been observed on the lab AD (no fixture plants that specific delegation),
// so this positive path was never proven with real data. Per Microsoft
// Learn ("Member attribute", win32/adschema/a-member) the schemaIDGUID for
// the "member" attribute is bf9679c0-0de6-11d0-a285-00aa003049e2, and
// ADS_RIGHT_DS_WRITE_PROP (the WriteProperty right) is 0x00000020 -
// matching this detector's memberGUID and writeProperty constants exactly.
// This test constructs a synthetic ACE combining both and proves the
// detector recognizes it, closing the "never triggered positively" gap
// without needing a real AD plant.
const (
	addMemberGroupDN = "CN=Domain Admins,CN=Users,DC=example,DC=com"
	addMemberGUID    = "bf9679c0-0de6-11d0-a285-00aa003049e2"
	addMemberTrustee = "S-1-5-21-1234567890-1111111111-2222222222-1105"
)

func addMemberData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		ObjectByDN: map[string]*audit.ObjectMeta{
			addMemberGroupDN: {DN: addMemberGroupDN, Name: "Domain Admins", EntityType: types.EntityTypeGroup},
		},
	}
}

func TestAddMember_WriteMemberGUIDRecognized(t *testing.T) {
	t.Run("WriteProperty + member GUID (mixed case) DOES fire", func(t *testing.T) {
		findings := NewAddMemberDetector().Detect(context.Background(), addMemberData(
			types.ACLEntry{
				ObjectDN:   addMemberGroupDN,
				Trustee:    addMemberTrustee,
				ObjectType: "BF9679C0-0DE6-11D0-A285-00AA003049E2", // uppercase, matching should be case-insensitive
				AccessMask: 0x20,                                   // ADS_RIGHT_DS_WRITE_PROP only
				AceType:    "ACCESS_ALLOWED_OBJECT",
			},
		))
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 1 {
			t.Fatalf("a WriteProperty grant scoped to the member GUID must fire, got count=%d", findings[0].Count)
		}
		if len(findings[0].AffectedEntities) != 1 {
			t.Fatalf("finding must be actionable, got %d entities", len(findings[0].AffectedEntities))
		}
	})

	t.Run("WriteProperty on a different attribute GUID does NOT fire", func(t *testing.T) {
		findings := NewAddMemberDetector().Detect(context.Background(), addMemberData(
			types.ACLEntry{
				ObjectDN:   addMemberGroupDN,
				Trustee:    addMemberTrustee,
				ObjectType: "00299570-246d-11d0-a768-00aa006e0529", // User-Force-Change-Password, unrelated
				AccessMask: 0x20,
				AceType:    "ACCESS_ALLOWED_OBJECT",
			},
		))
		if findings[0].Count != 0 {
			t.Fatalf("a WriteProperty grant on an unrelated attribute must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("member GUID without WriteProperty bit does NOT fire", func(t *testing.T) {
		findings := NewAddMemberDetector().Detect(context.Background(), addMemberData(
			types.ACLEntry{
				ObjectDN:   addMemberGroupDN,
				Trustee:    addMemberTrustee,
				ObjectType: addMemberGUID,
				AccessMask: 0x10, // ReadProperty only, not WriteProperty
				AceType:    "ACCESS_ALLOWED_OBJECT",
			},
		))
		if findings[0].Count != 0 {
			t.Fatalf("a read-only grant on the member GUID must not fire, got count=%d", findings[0].Count)
		}
	})
}

// Mutation-kill subtests, lab-proof companion to a live DC01 ACE plant on
// three disposable groups. Each fixture is a literal distinct from the
// detector's own unexported constants (never the same constant built and
// compared against itself) and targets exactly one rehearsed mutation of
// add-member.go: a swapped memberGUID, an inverted WriteProperty bit check,
// and a dropped ObjectType condition.
func TestAddMember_MutationCoverage(t *testing.T) {
	t.Run("lowercase member GUID with WriteProperty alone fires (kills M1: memberGUID swapped to a wrong value)", func(t *testing.T) {
		findings := NewAddMemberDetector().Detect(context.Background(), addMemberData(
			types.ACLEntry{
				ObjectDN:   addMemberGroupDN,
				Trustee:    addMemberTrustee,
				ObjectType: "bf9679c0-0de6-11d0-a285-00aa003049e2",
				AccessMask: 0x20,
				AceType:    "ACCESS_ALLOWED_OBJECT",
			},
		))
		if findings[0].Count != 1 {
			t.Fatalf("WriteProperty scoped to the real member GUID must fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("DS_SELF alone (no WriteProperty bit) on the member GUID does NOT fire (kills M2: 0x20 check inverted)", func(t *testing.T) {
		findings := NewAddMemberDetector().Detect(context.Background(), addMemberData(
			types.ACLEntry{
				ObjectDN:   addMemberGroupDN,
				Trustee:    addMemberTrustee,
				ObjectType: addMemberGUID,
				AccessMask: 0x08, // ADS_RIGHT_DS_SELF only - the WriteProperty bit (0x20) is absent
				AceType:    "ACCESS_ALLOWED_OBJECT",
			},
		))
		if findings[0].Count != 0 {
			t.Fatalf("a grant missing the WriteProperty bit must not fire even on the member GUID, got count=%d", findings[0].Count)
		}
	})

	t.Run("WriteProperty on the User-Force-Change-Password extended right does NOT fire (kills M3: ObjectType condition dropped)", func(t *testing.T) {
		findings := NewAddMemberDetector().Detect(context.Background(), addMemberData(
			types.ACLEntry{
				ObjectDN:   addMemberGroupDN,
				Trustee:    addMemberTrustee,
				ObjectType: "00299570-246d-11d0-a768-00aa006e0529", // User-Force-Change-Password, unrelated to member
				AccessMask: 0x20,
				AceType:    "ACCESS_ALLOWED_OBJECT",
			},
		))
		if findings[0].Count != 0 {
			t.Fatalf("WriteProperty on an unrelated extended right must not fire regardless of the mask, got count=%d", findings[0].Count)
		}
	})
}
