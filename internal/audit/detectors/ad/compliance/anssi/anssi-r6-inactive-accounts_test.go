package anssi

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

var r6TestNow = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// TestR6InactiveAccounts_ActiveUserNotReportedAsDisabled reproduces the bug
// end-to-end through the detector: before the fix, an active (non-disabled)
// user inactive for 91 days came back from the detector with
// AffectedEntities[0].Enabled == false, indistinguishable from a genuinely
// disabled account.
func TestR6InactiveAccounts_ActiveUserNotReportedAsDisabled(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	staleLogon := now.AddDate(0, 0, -91)
	data := &audit.DetectorData{
		Now:            now,
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=Active,DC=lab,DC=local", SAMAccountName: "active", Disabled: false, LastLogonTimestamp: staleLogon},
		},
	}
	findings := NewR6InactiveAccountsDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 || len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("expected 1 finding with 1 affected entity, got %+v", findings)
	}
	if !findings[0].AffectedEntities[0].Enabled {
		t.Errorf("active-but-inactive user reported as Enabled=false; it must be published as enabled since it can still authenticate")
	}
}

func TestR6InactiveAccounts_FiresOnOldEnabledNonZero(t *testing.T) {
	data := &audit.DetectorData{
		Now: r6TestNow,
		Users: []types.User{
			{DN: "CN=old-active,DC=lab,DC=local", Disabled: false, LastLogonTimestamp: r6TestNow.AddDate(0, 0, -100)},
		},
	}
	findings := NewR6InactiveAccountsDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected an active account inactive for 100 days to be flagged, got %+v", findings)
	}
}

func TestR6InactiveAccounts_RecentDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		Now: r6TestNow,
		Users: []types.User{
			{DN: "CN=recent-active,DC=lab,DC=local", Disabled: false, LastLogonTimestamp: r6TestNow.AddDate(0, 0, -10)},
		},
	}
	findings := NewR6InactiveAccountsDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected an account active 10 days ago to not be flagged, got %+v", findings)
	}
}

func TestR6InactiveAccounts_DisabledOldDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		Now: r6TestNow,
		Users: []types.User{
			{DN: "CN=old-disabled,DC=lab,DC=local", Disabled: true, LastLogonTimestamp: r6TestNow.AddDate(0, 0, -100)},
		},
	}
	findings := NewR6InactiveAccountsDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected a disabled account to never be flagged regardless of age, got %+v", findings)
	}
}

func TestR6InactiveAccounts_NeverLoggedOnDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		Now: r6TestNow,
		Users: []types.User{
			{DN: "CN=never-logged-on,DC=lab,DC=local", Disabled: false},
		},
	}
	findings := NewR6InactiveAccountsDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected an account with zero-value LastLogon/LastLogonTimestamp to not be flagged, got %+v", findings)
	}
}

func TestR6InactiveAccounts_MaxPicksRecentLastLogonOverOldTimestamp(t *testing.T) {
	data := &audit.DetectorData{
		Now: r6TestNow,
		Users: []types.User{
			{
				DN:                 "CN=old-timestamp-recent-logon,DC=lab,DC=local",
				Disabled:           false,
				LastLogonTimestamp: r6TestNow.AddDate(0, 0, -100),
				LastLogon:          r6TestNow.AddDate(0, 0, -10),
			},
		},
	}
	findings := NewR6InactiveAccountsDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected max(LastLogon, LastLogonTimestamp) to use the more recent LastLogon and not flag, got %+v", findings)
	}
}
