package status

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestPreCreated_DetectsUACCombinationWithoutRequiringDisabled(t *testing.T) {
	t.Run("active account with UAC 4128 DOES fire", func(t *testing.T) {
		// PASSWD_NOTREQD (0x20) + WORKSTATION_TRUST_ACCOUNT (0x1000) = 4128,
		// the recognized pre-staged-computer signature - the account is active.
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: "CN=WS-08,OU=Workstations,DC=example,DC=com", Disabled: false, UserAccountControl: 0x1020},
			},
		}
		findings := NewPreCreatedDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 1 {
			t.Fatalf("an active pre-staged account must fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled account without the UAC combination does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: "CN=WS-09,OU=Workstations,DC=example,DC=com", Disabled: true, UserAccountControl: 0x0002},
			},
		}
		findings := NewPreCreatedDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 0 {
			t.Fatalf("Disabled alone is not the pre-created signature anymore, got count=%d", findings[0].Count)
		}
	})

	t.Run("only PASSWD_NOTREQD without WORKSTATION_TRUST_ACCOUNT does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: "CN=WS-10,OU=Workstations,DC=example,DC=com", UserAccountControl: 0x0020},
			},
		}
		findings := NewPreCreatedDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 0 {
			t.Fatalf("the full UAC combination is required, got count=%d", findings[0].Count)
		}
	})

	t.Run("only WORKSTATION_TRUST_ACCOUNT without PASSWD_NOTREQD does NOT fire", func(t *testing.T) {
		// UAC 4096 (0x1000 alone). Misses bit 0x20.
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: "CN=WS-11,OU=Workstations,DC=example,DC=com", UserAccountControl: 4096},
			},
		}
		findings := NewPreCreatedDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 0 {
			t.Fatalf("WORKSTATION_TRUST_ACCOUNT alone must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("NORMAL_ACCOUNT plus PASSWD_NOTREQD without WORKSTATION_TRUST_ACCOUNT does NOT fire", func(t *testing.T) {
		// UAC 544 (0x220 = NORMAL_ACCOUNT + PASSWD_NOTREQD, a user-like account).
		// Misses bit 0x1000.
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: "CN=WS-12,OU=Workstations,DC=example,DC=com", UserAccountControl: 544},
			},
		}
		findings := NewPreCreatedDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 0 {
			t.Fatalf("NORMAL_ACCOUNT+PASSWD_NOTREQD without WORKSTATION_TRUST_ACCOUNT must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("full combination on a DISABLED account still fires - no Disabled guard", func(t *testing.T) {
		// UAC 4130 (0x1022 = ACCOUNTDISABLE + PASSWD_NOTREQD + WORKSTATION_TRUST_ACCOUNT).
		// Proves the detector carries no Disabled guard: the bitmask alone decides, per
		// the code comment on preCreatedUAC.
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: "CN=WS-13,OU=Workstations,DC=example,DC=com", Disabled: true, UserAccountControl: 4130},
			},
		}
		findings := NewPreCreatedDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 1 {
			t.Fatalf("a disabled account carrying the full UAC combination must still fire, got count=%d", findings[0].Count)
		}
	})
}
