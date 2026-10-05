package kerberos

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAsrepRoastingRisk covers the AND condition (account active, i.e. NOT
// Disabled, DONT_REQ_PREAUTH bit 0x400000 set). All fixtures use hardcoded
// UAC literals, never types.UACDontRequirePreauth, so a drift in that
// constant could never make this test pass by construction.
func TestAsrepRoastingRisk(t *testing.T) {
	userDN := "CN=svc,OU=Services,DC=test,DC=local"

	t.Run("active, UAC 0x400200 fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: false, UserAccountControl: 0x400200},
			},
			IncludeDetails: true,
		}
		findings := NewAsrepRoastingRiskDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 1 {
			t.Fatalf("active account with UAC 0x400200 must fire, got %+v", findings)
		}
		if findings[0].Type != "ASREP_ROASTING_RISK" {
			t.Fatalf("finding type must stay ASREP_ROASTING_RISK, got %s", findings[0].Type)
		}
		if findings[0].Severity != types.SeverityCritical {
			t.Fatalf("severity must stay Critical, got %s", findings[0].Severity)
		}
	})

	t.Run("active, UAC 0x410200 fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: false, UserAccountControl: 0x410200},
			},
		}
		findings := NewAsrepRoastingRiskDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("active account with UAC 0x410200 must fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled, UAC 0x400202 does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, UserAccountControl: 0x400202},
			},
		}
		findings := NewAsrepRoastingRiskDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("disabled account (even with the bit set) must not fire here, got count=%d", findings[0].Count)
		}
	})

	t.Run("active, UAC 0x200 (no preauth bit) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: false, UserAccountControl: 0x200},
			},
		}
		findings := NewAsrepRoastingRiskDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("active account without the preauth bit must not fire, got count=%d", findings[0].Count)
		}
	})

	// 0x200000 (bit 21) is USE_DES_KEY_ONLY, the immediate neighboring bit
	// below 0x400000 (bit 22). Pins that the mask is exactly 0x400000, not a
	// wider range that would also catch this neighbor.
	t.Run("active, UAC 0x200200 (neighbor bit USE_DES_KEY_ONLY) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: false, UserAccountControl: 0x200200},
			},
		}
		findings := NewAsrepRoastingRiskDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("active account carrying only the neighboring 0x200000 bit must not fire, got count=%d", findings[0].Count)
		}
	})

	// 0x800000 (bit 23) is PASSWORD_EXPIRED, the immediate neighboring bit
	// above 0x400000 (bit 22). Same purpose as the previous case, on the
	// other side of the mask.
	t.Run("active, UAC 0x800200 (neighbor bit PASSWORD_EXPIRED) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: false, UserAccountControl: 0x800200},
			},
		}
		findings := NewAsrepRoastingRiskDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("active account carrying only the neighboring 0x800000 bit must not fire, got count=%d", findings[0].Count)
		}
	})
}
