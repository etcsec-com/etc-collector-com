package moderate

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	wsaComputerDN  = "CN=WS-02,OU=Workstations,DC=example,DC=com"
	wsaGUID        = "f3a64788-5306-11d1-a9c5-0000f80367c1"
	wsaOrdinary    = "S-1-5-21-1234567890-1111111111-2222222222-1106"
	wsaBuiltinSelf = "S-1-5-10"

	wsaWriteProp = 0x00000020
	wsaReadProp  = 0x00000010
)

func wsaData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		ObjectByDN: map[string]*audit.ObjectMeta{
			wsaComputerDN: {DN: wsaComputerDN, Name: "WS-02", EntityType: types.EntityTypeComputer},
		},
	}
}

func wsaDetect(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewWriteSPNAbuseDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

func TestWriteSPNAbuse_RequiresGrantAndWriteBit(t *testing.T) {
	t.Run("DENY ace with the SPN GUID does NOT fire", func(t *testing.T) {
		f := wsaDetect(t, wsaData(
			types.ACLEntry{ObjectDN: wsaComputerDN, Trustee: wsaOrdinary, ObjectType: wsaGUID, AccessMask: wsaWriteProp, AceType: "ACCESS_DENIED"},
		))
		if f.Count != 0 {
			t.Fatalf("a DENY ace grants nothing, got count=%d", f.Count)
		}
	})

	t.Run("ALLOW ace without the write bit does NOT fire", func(t *testing.T) {
		f := wsaDetect(t, wsaData(
			types.ACLEntry{ObjectDN: wsaComputerDN, Trustee: wsaOrdinary, ObjectType: wsaGUID, AccessMask: wsaReadProp, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("read-only access to the SPN property is not an abuse, got count=%d", f.Count)
		}
	})

	t.Run("builtin trustee (SELF) does NOT fire", func(t *testing.T) {
		f := wsaDetect(t, wsaData(
			types.ACLEntry{ObjectDN: wsaComputerDN, Trustee: wsaBuiltinSelf, ObjectType: wsaGUID, AccessMask: wsaWriteProp, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("SELF writing its own SPN is expected, got count=%d", f.Count)
		}
	})

	t.Run("ALLOW ace with the write bit for an ordinary trustee DOES fire", func(t *testing.T) {
		f := wsaDetect(t, wsaData(
			types.ACLEntry{ObjectDN: wsaComputerDN, Trustee: wsaOrdinary, ObjectType: wsaGUID, AccessMask: wsaWriteProp, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("a real SPN-write delegation must fire, got count=%d", f.Count)
		}
		if len(f.AffectedEntities) != 1 {
			t.Fatalf("finding must be actionable, got %d entities", len(f.AffectedEntities))
		}
	})
}
