package privileged

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// T_064/B_055 — proves the frozen-bench reproducibility property: replaying
// the same captured AdminLastLoginDate against the same injected reference
// time (data.Now) yields an identical finding, independent of the real
// wall-clock date the test happens to run on. Detect() no longer calls
// time.Now()/time.Since() at all — data.Now is the only time input it reads.

func detectAdminNativeRecentLogon(now, lastLogin time.Time) types.Finding {
	data := &audit.DetectorData{
		Now: now,
		DomainInfo: &types.DomainInfo{
			AdminLastLoginDate: lastLogin,
		},
	}
	findings := NewAdminNativeRecentLogonDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		panic("expected exactly one finding")
	}
	return findings[0]
}

func TestAdminNativeRecentLogon_ReplayIsDeterministicAcrossRealDates(t *testing.T) {
	lastLogin := time.Date(2026, 7, 29, 9, 31, 0, 0, time.UTC) // the frozen bench's own capture instant
	asOf := lastLogin.Add(17 * 24 * time.Hour)                 // the bench's own "as of" timestamp — 17 days later

	first := detectAdminNativeRecentLogon(asOf, lastLogin)

	// Simulate "replay on a different real calendar day": real wall-clock
	// time has moved on since `first` was computed, but the bench's own AsOf
	// is fixed data, not time.Now() — so the second replay must reproduce
	// byte-for-byte, no matter how much real time elapses between the two.
	time.Sleep(2 * time.Millisecond)
	second := detectAdminNativeRecentLogon(asOf, lastLogin)

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("replaying the identical frozen input produced different findings:\nfirst:  %+v\nsecond: %+v", first, second)
	}

	// Same relative gap (17 days), but the reference time itself is a
	// completely different calendar date — proves the outcome depends only
	// on (Now - AdminLastLoginDate), never on which real date Now is.
	shiftedAsOf := asOf.AddDate(3, 0, 0)
	shiftedLastLogin := lastLogin.AddDate(3, 0, 0)
	shifted := detectAdminNativeRecentLogon(shiftedAsOf, shiftedLastLogin)

	if first.Count != shifted.Count || first.Description != shifted.Description {
		t.Fatalf("shifting both timestamps by the same amount changed the result:\nfirst:   %+v\nshifted: %+v", first, shifted)
	}
}

func TestAdminNativeRecentLogon_ThirtyDayThresholdUnchanged(t *testing.T) {
	if adminRecentThreshold != 30*24*time.Hour {
		t.Fatalf("adminRecentThreshold must stay exactly 30 days — T_064 forbids touching the business threshold, got %v", adminRecentThreshold)
	}

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name      string
		daysAgo   int
		wantCount int
	}{
		{"29 days ago — within threshold", 29, 1},
		{"exactly 30 days ago — boundary, no longer recent", 30, 0},
		{"31 days ago — outside threshold", 31, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lastLogin := base.Add(-time.Duration(tc.daysAgo) * 24 * time.Hour)
			f := detectAdminNativeRecentLogon(base, lastLogin)
			if f.Count != tc.wantCount {
				t.Fatalf("daysAgo=%d: got Count=%d, want %d", tc.daysAgo, f.Count, tc.wantCount)
			}
		})
	}
}

func TestAdminNativeRecentLogon_ZeroAdminLastLoginDate_NoFinding(t *testing.T) {
	f := detectAdminNativeRecentLogon(time.Now(), time.Time{})
	if f.Count != 0 {
		t.Fatalf("zero AdminLastLoginDate (never collected) should not count as recent, got Count=%d", f.Count)
	}
}
