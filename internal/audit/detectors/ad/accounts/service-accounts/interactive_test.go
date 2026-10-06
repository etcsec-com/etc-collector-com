package serviceaccounts

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestInteractive_PasswordNeverExpiresAloneNotFlagged pins the removal of
// the old UAC-flag branch: a service account with an old lastLogon but
// UAC_DONT_EXPIRE_PASSWD set (and delegation allowed) used to fire even
// though nothing about those flags indicates interactive logon. It must
// not fire now that only recent authentication activity is considered.
func TestInteractive_PasswordNeverExpiresAloneNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				SAMAccountName:        "svc-report",
				ServicePrincipalNames: []string{"HOST/svc-report"},
				LastLogon:             now.AddDate(0, -6, 0), // 6 months ago: not recent
				UserAccountControl:    types.UACDontExpirePassword,
			},
		},
	}

	findings := NewInteractiveDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: password-never-expires alone is not evidence of interactive logon", findings[0].Count)
	}
}

// TestInteractive_RecentAuthenticationFlagged pins the surviving signal:
// a service-looking account that authenticated within the last 30 days
// still fires, honestly labeled as a review signal.
func TestInteractive_RecentAuthenticationFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now:            now,
		IncludeDetails: true,
		Users: []types.User{
			{
				SAMAccountName:        "svc-report",
				ServicePrincipalNames: []string{"HOST/svc-report"},
				LastLogon:             now.AddDate(0, 0, -1),
			},
		},
	}

	findings := NewInteractiveDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: recent authentication on a service account is the (weak, disclosed) signal this detector reports", findings[0].Count)
	}
}

// TestInteractive_PatternOnlyNoSPNRecentFlagged pins that a naming-pattern
// match alone (no SPN at all) with recent authentication is sufficient.
func TestInteractive_PatternOnlyNoSPNRecentFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				SAMAccountName: "svc_t494a",
				LastLogon:      now.AddDate(0, 0, -1),
			},
		},
	}

	findings := NewInteractiveDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: naming pattern alone (no SPN) with recent lastLogon fires", findings[0].Count)
	}
}

// TestInteractive_DisabledSvcAccountNotFlagged pins the Disabled guard
// (MUTATION M1 target): a disabled account matching the service pattern,
// with an SPN and a recent lastLogon, must not fire.
func TestInteractive_DisabledSvcAccountNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				SAMAccountName:        "svc_t494disabled",
				ServicePrincipalNames: []string{"HTTP/svc_t494disabled.lab.local"},
				LastLogon:             now.AddDate(0, 0, -1),
				Disabled:              true,
			},
		},
	}

	findings := NewInteractiveDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a disabled account must not fire regardless of SPN, pattern or lastLogon", findings[0].Count)
	}
}

// TestInteractive_NonServiceNameWithSPNFlagged pins the "hasSPN OR pattern"
// disjunction (MUTATION M2 target): an account whose name matches no
// service pattern still fires on SPN alone.
func TestInteractive_NonServiceNameWithSPNFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				SAMAccountName:        "t494nonsvc",
				ServicePrincipalNames: []string{"HOST/t494nonsvc.lab.local"},
				LastLogon:             now.AddDate(0, 0, -1),
			},
		},
	}

	findings := NewInteractiveDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: SPN alone is sufficient even without a service-looking name", findings[0].Count)
	}
}

// TestInteractive_ZeroLastLogonNotFlagged pins that an account which has
// never authenticated (LastLogon left at its zero value) must not fire.
func TestInteractive_ZeroLastLogonNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				SAMAccountName:        "svc_t494b",
				ServicePrincipalNames: []string{"HTTP/svc_t494b.lab.local"},
				// LastLogon intentionally left zero-value: never authenticated.
			},
		},
	}

	findings := NewInteractiveDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: zero LastLogon means never authenticated, must not fire", findings[0].Count)
	}
}

// TestInteractive_LastLogonOverThirtyDaysNotFlagged pins the outer edge of
// the 30-day window: authentication 31 days ago must not fire.
func TestInteractive_LastLogonOverThirtyDaysNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				SAMAccountName:        "svc_t494old",
				ServicePrincipalNames: []string{"HTTP/svc_t494old.lab.local"},
				LastLogon:             now.AddDate(0, 0, -31),
			},
		},
	}

	findings := NewInteractiveDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: lastLogon older than 30 days must not fire", findings[0].Count)
	}
}

// TestInteractive_TenDaysAgoFlagged pins the actual width of the 30-day
// window (MUTATION M3 target): authentication 10 days ago fires under the
// real 30-day window but would not under a narrowed 1-day window.
func TestInteractive_TenDaysAgoFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				SAMAccountName:        "svc_t494window",
				ServicePrincipalNames: []string{"HTTP/svc_t494window.lab.local"},
				LastLogon:             now.AddDate(0, 0, -10),
			},
		},
	}

	findings := NewInteractiveDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: lastLogon 10 days ago is within the real 30-day window", findings[0].Count)
	}
}
