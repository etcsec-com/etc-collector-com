package moderate

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ACL_GENERICWRITE tested only the raw GENERIC_WRITE bit
// (0x40000000), which Windows almost never writes to an ACE: it maps generic
// bits to specific rights at write time, so the detector was structurally
// mute (0 findings on DC01, 1128 objects / 41269 ACEs, confirmed live
// 2026-09-08). Fixing the mask alone would have flipped it the other way -
// genericall.go's note documents 1134/1167 objects without the grant +
// builtin-admin filters - so both land in this one change.

const (
	gwDomainDN = "DC=example,DC=com"
	gwDomain   = "S-1-5-21-1234567890-1111111111-2222222222"
	gwUserDN   = "CN=Akira Jackson,OU=IT," + gwDomainDN

	gwSidSystem       = "S-1-5-18"
	gwSidBuiltinAdmin = "S-1-5-32-544"
	gwSidDomainAdmins = gwDomain + "-512"
	gwSidOrdinary     = gwDomain + "-93801"

	// GenericWrite mapped to AD-specific rights (READ_CONTROL | ACTRL_DS_WRITE_PROP
	// | ACTRL_DS_SELF) - what dsacls/.NET actually write. See genericwrite.go.
	gwMaskMapped = 0x00020028
	gwMaskRaw    = 0x40000000
)

func gwData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		ObjectByDN: map[string]*audit.ObjectMeta{
			gwUserDN:   {DN: gwUserDN, Name: "Akira Jackson", EntityType: types.EntityTypeUser},
			gwDomainDN: {DN: gwDomainDN, Name: "example", EntityType: types.EntityTypeDomain},
		},
	}
}

func gwDetect(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	d := NewGenericWriteDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// TestGenericWrite_MappedMaskFires is the RED->GREEN case: before the fix the
// detector tested only the raw 0x40000000 bit, which this ACE does not carry,
// so it never fired even though the trustee genuinely holds GenericWrite.
func TestGenericWrite_MappedMaskFires(t *testing.T) {
	f := gwDetect(t, gwData(
		types.ACLEntry{ObjectDN: gwUserDN, Trustee: gwSidOrdinary, AccessMask: gwMaskMapped, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 1 {
		t.Fatalf("a trustee holding the AD-mapped GenericWrite mask must fire, got count=%d", f.Count)
	}
	if len(f.AffectedEntities) != 1 {
		t.Fatalf("finding must be actionable, got %d entities", len(f.AffectedEntities))
	}
}

// TestGenericWrite_RawBitStillFires guards the pre-existing (if rare) raw-bit path.
func TestGenericWrite_RawBitStillFires(t *testing.T) {
	f := gwDetect(t, gwData(
		types.ACLEntry{ObjectDN: gwUserDN, Trustee: gwSidOrdinary, AccessMask: gwMaskRaw, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 1 {
		t.Fatalf("the raw GENERIC_WRITE bit must still fire, got count=%d", f.Count)
	}
}

// TestGenericWrite_DenyDoesNotFire covers DET_10: a DENY ace grants nothing.
func TestGenericWrite_DenyDoesNotFire(t *testing.T) {
	f := gwDetect(t, gwData(
		types.ACLEntry{ObjectDN: gwUserDN, Trustee: gwSidOrdinary, AccessMask: gwMaskMapped, AceType: "ACCESS_DENIED"},
	))
	if f.Count != 0 {
		t.Fatalf("a DENY ace must not fire, got count=%d", f.Count)
	}
}

// TestGenericWrite_BuiltinAdminTrusteesDoNotFire is the trap this warns
// against: mapping the mask without this filter turns a mute detector into an
// always-on one (measured live: 100%% of 1128 DC01 objects without it).
func TestGenericWrite_BuiltinAdminTrusteesDoNotFire(t *testing.T) {
	f := gwDetect(t, gwData(
		types.ACLEntry{ObjectDN: gwUserDN, Trustee: gwSidSystem, AccessMask: gwMaskMapped, AceType: "ACCESS_ALLOWED"},
		types.ACLEntry{ObjectDN: gwUserDN, Trustee: gwSidDomainAdmins, AccessMask: gwMaskMapped, AceType: "ACCESS_ALLOWED"},
		types.ACLEntry{ObjectDN: gwUserDN, Trustee: gwSidBuiltinAdmin, AccessMask: gwMaskMapped, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 0 {
		t.Fatalf("AD's own baseline ACEs must not be findings, got count=%d", f.Count)
	}
}
