package anssi

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestR7StaleAccounts_NeverLoggedOnFallsBackToCreated: a
// disabled account that never logged on has LastLogon/LastLogonTimestamp
// both zero. The detector used to require `!last.IsZero()` before comparing
// to the threshold, so a never-used disabled account - the worst case for
// this check, not a safe one - was silently skipped forever. This test would
// have FAILED against the old implementation (no finding) and passes now
// that a zero last-logon falls back to Created (whenCreated).
func TestR7StaleAccounts_NeverLoggedOnFallsBackToCreated(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:             "CN=Never Used,DC=lab,DC=local",
				SAMAccountName: "neverused",
				Disabled:       true,
				Created:        now.AddDate(0, 0, -200), // created 200 days ago, never logged on
			},
		},
	}
	findings := NewR7StaleAccountsNotRemovedDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a disabled, never-logged-on account created 200 days ago to be flagged, got %+v", findings)
	}
}
