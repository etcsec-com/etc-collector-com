package moderate

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	wvdOUComputerDN  = "CN=WS-03,OU=Workstations,DC=example,DC=com"
	wvdDefaultCompDN = "CN=WS-04,CN=Computers,DC=example,DC=com"
	wvdUserDN        = "CN=Akira Jackson,OU=IT,DC=example,DC=com"
	wvdGUID          = "72e39547-7b18-11d1-adef-00c04fd8d5cd"
	wvdTrustee       = "S-1-5-21-1234567890-1111111111-2222222222-1107"
)

func wvdData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		Computers: []types.Computer{
			{DN: wvdOUComputerDN, SAMAccountName: "WS-03$"},
			{DN: wvdDefaultCompDN, SAMAccountName: "WS-04$"},
		},
		ObjectByDN: map[string]*audit.ObjectMeta{
			wvdOUComputerDN:  {DN: wvdOUComputerDN, Name: "WS-03", EntityType: types.EntityTypeComputer},
			wvdDefaultCompDN: {DN: wvdDefaultCompDN, Name: "WS-04", EntityType: types.EntityTypeComputer},
		},
	}
}

func wvdDetect(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewWriteValidatedDNSDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

func TestWriteValidatedDNS_NotRestrictedToDefaultContainer(t *testing.T) {
	t.Run("a computer in a custom OU DOES fire", func(t *testing.T) {
		f := wvdDetect(t, wvdData(
			types.ACLEntry{ObjectDN: wvdOUComputerDN, Trustee: wvdTrustee, ObjectType: wvdGUID, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("a computer outside CN=Computers is still a computer, got count=%d", f.Count)
		}
	})

	t.Run("a computer in the default container still fires", func(t *testing.T) {
		f := wvdDetect(t, wvdData(
			types.ACLEntry{ObjectDN: wvdDefaultCompDN, Trustee: wvdTrustee, ObjectType: wvdGUID, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("the default container must remain covered, got count=%d", f.Count)
		}
	})

	t.Run("a non-computer object does NOT fire", func(t *testing.T) {
		f := wvdDetect(t, wvdData(
			types.ACLEntry{ObjectDN: wvdUserDN, Trustee: wvdTrustee, ObjectType: wvdGUID, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("a user object is not this detector's business, got count=%d", f.Count)
		}
	})
}
