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
}
