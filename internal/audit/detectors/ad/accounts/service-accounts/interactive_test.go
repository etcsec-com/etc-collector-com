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
