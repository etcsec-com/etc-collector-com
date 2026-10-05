package status

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// same lastLogon (per-DC, never replicated) vs lastLogonTimestamp
// (replicated) fix as STALE_ACCOUNT, at the 365-day threshold.

func TestInactive365_OldLastLogonRecentTimestamp_NoLongerFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	u := types.User{
		LastLogon:          now.AddDate(-2, 0, 0), // 2 years ago on this one DC
		LastLogonTimestamp: now.AddDate(0, 0, -10),
	}
	data := &audit.DetectorData{Now: now, Users: []types.User{u}}

	f := NewInactive365Detector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("stale lastLogon but recent lastLogonTimestamp must NOT be flagged, got Count=%d", f.Count)
	}
}

func TestInactive365_RecentLastLogonOldTimestamp_Flagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	u := types.User{
		LastLogon:          now.AddDate(0, 0, -5),
		LastLogonTimestamp: now.AddDate(-2, 0, 0),
	}
	data := &audit.DetectorData{Now: now, Users: []types.User{u}}

	f := NewInactive365Detector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("recent lastLogon but stale lastLogonTimestamp MUST be flagged, got Count=%d", f.Count)
	}
}

func TestInactive365_ReplicationToleranceBoundary(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	oneYearAgo := now.AddDate(-1, 0, 0)

	cases := []struct {
		name      string
		timestamp time.Time
		wantCount int
	}{
		{"exactly at 365 days - within the 14-day replication tolerance, not flagged", oneYearAgo, 0},
		{"365 days + 13 days - still within tolerance, not flagged", oneYearAgo.AddDate(0, 0, -13), 0},
		{"365 days + 15 days - past tolerance, flagged", oneYearAgo.AddDate(0, 0, -15), 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := types.User{LastLogonTimestamp: tc.timestamp}
			data := &audit.DetectorData{Now: now, Users: []types.User{u}}
			f := NewInactive365Detector().Detect(context.Background(), data)[0]
			if f.Count != tc.wantCount {
				t.Fatalf("expected Count=%d, got %d", tc.wantCount, f.Count)
			}
		})
	}
}

func TestInactive365_ZeroLastLogonTimestamp_NotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	u := types.User{LastLogon: now.AddDate(-2, 0, 0)}
	data := &audit.DetectorData{Now: now, Users: []types.User{u}}

	f := NewInactive365Detector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("zero lastLogonTimestamp must not be flagged by this detector, got Count=%d", f.Count)
	}
}
