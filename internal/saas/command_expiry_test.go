package saas

import (
	"testing"
	"time"
)

// TestCommandExpiry_FailsClosed — A_004 K12. The previous logic was fail-OPEN by two
// paths: an empty ExpiresAt skipped the check entirely, and a parse error left the
// "expired?" condition false. Either one disabled the only freshness control on every
// command, UPDATE_COLLECTOR included. Only a parseable, not-yet-past timestamp may run.
func TestCommandExpiry_FailsClosed(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		expiresAt  string
		mayExecute bool
	}{
		{"empty — no proof of freshness", "", false},
		{"whitespace only", "   ", false},
		{"malformed", "not-a-date", false},
		{"unix epoch seconds (wrong format)", "1753704000", false},
		{"truncated timestamp", "2026-07-28T13:00", false},
		{"past RFC3339", "2026-07-28T11:00:00Z", false},
		{"past RFC3339Nano", "2026-07-28T11:59:59.999Z", false},
		{"exactly now is not yet past", "2026-07-28T12:00:00Z", true},
		{"future RFC3339", "2026-07-28T13:00:00Z", true},
		{"future RFC3339Nano (what the cloud actually sends)", "2026-07-28T13:00:00.079Z", true},
		{"future RFC3339 with offset", "2026-07-28T15:00:00+02:00", true},
		{"past RFC3339 with offset", "2026-07-28T13:00:00+02:00", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkCommandExpiry(tc.expiresAt, now)
			if tc.mayExecute && err != nil {
				t.Fatalf("expiresAt %q should allow execution, got error: %v", tc.expiresAt, err)
			}
			if !tc.mayExecute && err == nil {
				t.Fatalf("expiresAt %q must be REJECTED, but the command would execute", tc.expiresAt)
			}
		})
	}
}
