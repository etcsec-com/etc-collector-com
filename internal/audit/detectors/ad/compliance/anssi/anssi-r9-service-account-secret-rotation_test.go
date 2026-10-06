package anssi

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestR9ServiceAccountRotation_NeverSetPasswordIsFlagged: a
// service account with pwdLastSet=0 (password never actually set through
// normal rotation) is the worst case for secret staleness, not a safe one.
// The detector used to require `!u.PasswordLastSet.IsZero()` before
// comparing to the threshold, silently excluding exactly these accounts.
// This test would have FAILED against the old implementation (no finding)
// and passes now that a zero PasswordLastSet is treated as maximally stale.
func TestR9ServiceAccountRotation_NeverSetPasswordIsFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:                    "CN=svc-legacy,DC=lab,DC=local",
				SAMAccountName:        "svc-legacy",
				Disabled:              false,
				PasswordNeverExpires:  true,
				ServicePrincipalNames: []string{"HTTP/legacy.lab.local"},
				// PasswordLastSet intentionally left zero.
			},
		},
	}
	findings := NewR9ServiceAccountSecretRotationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a service account with pwdLastSet=0 to be flagged as never-rotated, got %+v", findings)
	}
}
