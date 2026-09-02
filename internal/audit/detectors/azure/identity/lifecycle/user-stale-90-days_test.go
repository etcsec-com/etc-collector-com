package lifecycle

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// T_069/B_176 — proves the frozen-bench reproducibility property (same one
// T_064/B_055 established for AD): replaying the same captured
// AzureLastSignInDateTime against the same injected reference time (data.Now)
// yields an identical finding, independent of the real wall-clock date the
// test happens to run on. Detect() no longer calls time.Now() at all —
// data.Now is the only time input it reads.

func detectUserStale(now, lastSignIn time.Time) types.Finding {
	ts := lastSignIn
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{{
			UserPrincipalName:       "stale@contoso.test",
			AzureLastSignInDateTime: &ts,
		}},
	}
	findings := NewUserStale90DaysDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		panic("expected exactly one finding")
	}
	return findings[0]
}

func TestUserStale90Days_ReplayIsDeterministicAcrossRealDates(t *testing.T) {
	lastSignIn := time.Date(2026, 5, 1, 8, 0, 0, 0, time.UTC)
	asOf := lastSignIn.Add(120 * 24 * time.Hour) // 120 days later — well past the 90-day threshold

	first := detectUserStale(asOf, lastSignIn)

	// Simulate "replay on a different real calendar day": real wall-clock time
	// has moved on since `first` was computed, but the bench's own AsOf is
	// fixed data, not time.Now() — so the second replay must reproduce
	// byte-for-byte, no matter how much real time elapses between the two.
	time.Sleep(2 * time.Millisecond)
	second := detectUserStale(asOf, lastSignIn)

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("replaying the identical frozen input produced different findings:\nfirst:  %+v\nsecond: %+v", first, second)
	}

	// Same relative gap (120 days), but the reference time itself is a
	// completely different calendar date — proves the outcome depends only on
	// (Now - AzureLastSignInDateTime), never on which real date Now is.
	shiftedAsOf := asOf.AddDate(3, 0, 0)
	shiftedLastSignIn := lastSignIn.AddDate(3, 0, 0)
	shifted := detectUserStale(shiftedAsOf, shiftedLastSignIn)

	if first.Count != shifted.Count {
		t.Fatalf("shifting both timestamps by the same amount changed the result:\nfirst:   %+v\nshifted: %+v", first, shifted)
	}
}

func TestUserStale90Days_NinetyDayThresholdUnchanged(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name      string
		daysAgo   int
		wantCount int
	}{
		{"89 days ago — within threshold, not stale", 89, 0},
		{"exactly 90 days ago — boundary, still not stale (strict Before)", 90, 0},
		{"91 days ago — outside threshold, stale", 91, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lastSignIn := base.Add(-time.Duration(tc.daysAgo) * 24 * time.Hour)
			f := detectUserStale(base, lastSignIn)
			if f.Count != tc.wantCount {
				t.Fatalf("daysAgo=%d: got Count=%d, want %d", tc.daysAgo, f.Count, tc.wantCount)
			}
		})
	}
}

func TestUserStale90Days_NeverSignedIn_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		Now:   time.Now(),
		Users: []types.User{{UserPrincipalName: "never@contoso.test"}}, // no AzureLastSignInDateTime
	}
	findings := NewUserStale90DaysDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("a user with no collected sign-in timestamp should not count as stale, got Count=%d", findings[0].Count)
	}
}

func TestUserStale90Days_DisabledUserIgnored(t *testing.T) {
	longAgo := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Users: []types.User{{
			UserPrincipalName:       "disabled@contoso.test",
			Disabled:                true,
			AzureLastSignInDateTime: &longAgo,
		}},
	}
	findings := NewUserStale90DaysDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("a disabled user should never count toward stale-active-account findings, got Count=%d", findings[0].Count)
	}
}
