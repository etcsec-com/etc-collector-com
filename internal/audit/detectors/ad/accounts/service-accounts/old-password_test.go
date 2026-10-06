package serviceaccounts

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestOldPassword_MustChangeAtNextLogonNotFlagged pins the fix: pwdLastSet
// == 0 means "must change password at next logon" (Microsoft Learn,
// Pwd-Last-Set attribute), not "password not changed in over a year". The
// collector maps that to a Go zero time.Time, which the old code counted
// as an old password - a freshly reset service account was mislabeled.
func TestOldPassword_MustChangeAtNextLogonNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				SAMAccountName:  "svc-newapp",
				PasswordLastSet: time.Time{}, // pwdLastSet=0: must change at next logon
			},
		},
	}

	findings := NewOldPasswordDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: pwdLastSet=0 is a pending forced change, not an old password", findings[0].Count)
	}
}

// TestOldPassword_GenuinelyStaleFlagged pins the surviving positive case: a
// real, non-zero timestamp older than a year must still fire.
func TestOldPassword_GenuinelyStaleFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now:            now,
		IncludeDetails: true,
		Users: []types.User{
			{
				SAMAccountName:  "svc-legacy",
				PasswordLastSet: now.AddDate(-2, 0, 0),
			},
		},
	}

	findings := NewOldPasswordDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: a real 2-year-old password must still fire", findings[0].Count)
	}
}
