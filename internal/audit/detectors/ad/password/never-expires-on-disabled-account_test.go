package password

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestNeverExpiresOnDisabledAccount_OnlyDisabledCounted mirrors
// TestNeverExpires_DisabledAccountExcluded from the sibling file: the two
// detectors must partition the same population with no overlap and no gap.
//
// Fixtures use realistic multi-bit UAC values (0x10200 active, 0x10202
// disabled) rather than the bare 0x10000 literal. The previous fixture pair
// used {UserAccountControl: 0x10000, Disabled: true} for the disabled case -
// an impossible AD state: a disabled account always carries bit 0x2
// (ACCOUNTDISABLE), so its UAC can never equal exactly 0x10000. That
// impossible fixture is exactly why a stray `uac == 0x10000` equality check
// used to survive: the equality happened to hold on a state real AD never
// produces.
func TestNeverExpiresOnDisabledAccount_OnlyDisabledCounted(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "active-svc", UserAccountControl: 0x10200, Disabled: false},
			{SAMAccountName: "stale-disabled", UserAccountControl: 0x10202, Disabled: true},
		},
	}

	findings := NewNeverExpiresOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (only the disabled account)", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityLow {
		t.Fatalf("Severity = %s, want low", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "stale-disabled" {
		t.Fatalf("AffectedEntities = %+v, want only stale-disabled", findings[0].AffectedEntities)
	}
}

// TestNeverExpiresOnDisabledAccount_EnabledNotFlagged guards the negative case.
func TestNeverExpiresOnDisabledAccount_EnabledNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "active-svc", UserAccountControl: 0x10000, Disabled: false}},
	}

	findings := NewNeverExpiresOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}
