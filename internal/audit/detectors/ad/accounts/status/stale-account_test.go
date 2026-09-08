package status

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// lastLogon is per-DC and never replicated, so its value is only
// ever "the truth according to whichever DC happened to answer this query".
// lastLogonTimestamp is replicated and designed exactly for stale-account
// detection, at the cost of lagging real activity by up to ~14 days.

func TestStaleAccount_OldLastLogonRecentTimestamp_NoLongerFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	u := types.User{
		LastLogon:          now.AddDate(0, -8, 0),  // 8 months ago on this one DC
		LastLogonTimestamp: now.AddDate(0, 0, -10), // replicated: actually active 10 days ago
	}
	data := &audit.DetectorData{Now: now, Users: []types.User{u}}

	f := NewStaleAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("stale lastLogon but recent lastLogonTimestamp must NOT be flagged, got Count=%d", f.Count)
	}
}

func TestStaleAccount_RecentLastLogonOldTimestamp_Flagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	u := types.User{
		LastLogon:          now.AddDate(0, 0, -5), // recent on this one DC
		LastLogonTimestamp: now.AddDate(0, -8, 0), // replicated: actually stale
	}
	data := &audit.DetectorData{Now: now, Users: []types.User{u}}

	f := NewStaleAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("recent lastLogon but stale lastLogonTimestamp MUST be flagged (domain-wide truth), got Count=%d", f.Count)
	}
}

func TestStaleAccount_ReplicationToleranceBoundary(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	sixMonthsAgo := now.AddDate(0, -6, 0)

	cases := []struct {
		name      string
		timestamp time.Time
		wantCount int
	}{
		{"exactly at 180 days - within the 14-day replication tolerance, not flagged", sixMonthsAgo, 0},
		{"180 days + 13 days - still within tolerance, not flagged", sixMonthsAgo.AddDate(0, 0, -13), 0},
		{"180 days + 15 days - past tolerance, flagged", sixMonthsAgo.AddDate(0, 0, -15), 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := types.User{LastLogonTimestamp: tc.timestamp}
			data := &audit.DetectorData{Now: now, Users: []types.User{u}}
			f := NewStaleAccountDetector().Detect(context.Background(), data)[0]
			if f.Count != tc.wantCount {
				t.Fatalf("expected Count=%d, got %d", tc.wantCount, f.Count)
			}
		})
	}
}

func TestStaleAccount_DisabledAccount_NotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	u := types.User{
		Disabled:           true,
		LastLogonTimestamp: now.AddDate(-2, 0, 0),
	}
	data := &audit.DetectorData{Now: now, Users: []types.User{u}}

	f := NewStaleAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("disabled accounts must not be flagged, got Count=%d", f.Count)
	}
}

func TestStaleAccount_ZeroLastLogonTimestamp_NotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	u := types.User{LastLogon: now.AddDate(-2, 0, 0)} // never-logged-on's job, not this detector's
	data := &audit.DetectorData{Now: now, Users: []types.User{u}}

	f := NewStaleAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("zero lastLogonTimestamp must not be flagged by this detector, got Count=%d", f.Count)
	}
}
