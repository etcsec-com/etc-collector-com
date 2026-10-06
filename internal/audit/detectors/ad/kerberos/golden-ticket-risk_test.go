package kerberos

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestGoldenTicketRiskDetector covers the exact condition read line by line
// from golden-ticket-risk.go: first user whose SAMAccountName == "krbtgt"
// (exact, case-sensitive match) is the krbtgt account; if absent or its
// PasswordLastSet is the zero value, Count stays 0 and Description is
// rewritten to the "or password date unavailable" variant; otherwise Count
// is 1 iff PasswordLastSet.Before(Now.AddDate(0, -6, 0)) - a 6 CALENDAR
// MONTH threshold (roughly 181 to 184 days depending on the month, never a
// fixed 180-day count). The published Description reads "6+ months",
// matching this threshold; the "180.5 days elapsed" case below pins the
// boundary that a fixed-180-day reading would get wrong.
//
// All fixtures use literal time.Date values, never a value computed from
// the detector's own AddDate call, so that a drift in that arithmetic cannot
// make a fixture pass by construction.
func TestGoldenTicketRiskDetector(t *testing.T) {
	d := NewGoldenTicketRiskDetector()

	t.Run("krbtgt ancien: password set 2025-01-01, Now 2026-09-25 (>6 months) -> counted", func(t *testing.T) {
		now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
		data := &audit.DetectorData{
			Now: now,
			Users: []types.User{
				{DN: "CN=krbtgt,CN=Users,DC=test,DC=local", SAMAccountName: "krbtgt", PasswordLastSet: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
		}
		findings := d.Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 1 {
			t.Fatalf("old krbtgt password must be counted, got %+v", findings)
		}
		wantDesc := "krbtgt account password unchanged for 6+ months. Enables persistent Golden Ticket attacks."
		if findings[0].Description != wantDesc {
			t.Fatalf("Description mismatch: got %q, want %q", findings[0].Description, wantDesc)
		}
	})

	t.Run("krbtgt recent: password set 2026-08-01, Now 2026-09-25 (<6 months) -> not counted", func(t *testing.T) {
		now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
		data := &audit.DetectorData{
			Now: now,
			Users: []types.User{
				{DN: "CN=krbtgt,CN=Users,DC=test,DC=local", SAMAccountName: "krbtgt", PasswordLastSet: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("recent krbtgt password must not be counted, got count=%d", findings[0].Count)
		}
	})

	// Exact boundary around Now.AddDate(0,-6,0). Now=2026-06-15T12:00:00Z has
	// no month-length overflow (June 15 - 6 months = December 15, both exist),
	// isolating the strict-Before comparison itself from the AddDate rollover
	// behavior covered separately below.
	t.Run("boundary: 1s before the 6-month threshold -> counted (old)", func(t *testing.T) {
		now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
		data := &audit.DetectorData{
			Now: now,
			Users: []types.User{
				{DN: "CN=krbtgt,CN=Users,DC=test,DC=local", SAMAccountName: "krbtgt", PasswordLastSet: time.Date(2025, 12, 15, 11, 59, 59, 0, time.UTC)},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("password set 1s before the threshold must be counted, got count=%d", findings[0].Count)
		}
	})

	t.Run("boundary: exactly on the 6-month threshold -> NOT counted (Before excludes equality)", func(t *testing.T) {
		now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
		data := &audit.DetectorData{
			Now: now,
			Users: []types.User{
				{DN: "CN=krbtgt,CN=Users,DC=test,DC=local", SAMAccountName: "krbtgt", PasswordLastSet: time.Date(2025, 12, 15, 12, 0, 0, 0, time.UTC)},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("password set exactly on the threshold instant must NOT be counted (strict Before), got count=%d", findings[0].Count)
		}
	})

	t.Run("boundary: 1s after the 6-month threshold -> not counted (recent)", func(t *testing.T) {
		now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
		data := &audit.DetectorData{
			Now: now,
			Users: []types.User{
				{DN: "CN=krbtgt,CN=Users,DC=test,DC=local", SAMAccountName: "krbtgt", PasswordLastSet: time.Date(2025, 12, 15, 12, 0, 1, 0, time.UTC)},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("password set 1s after the threshold must not be counted, got count=%d", findings[0].Count)
		}
	})

	// End-of-month: AddDate(0,-6,0) does NOT clamp to the last real day of
	// the target month, it carries the day-of-month overflow forward into
	// the following month (verified live with `go run`: 2026-08-31 minus 6
	// months lands on 2026-03-03, not on 2026-02-28). A password set on
	// 2026-03-01 - which a "clamp to Feb 28" reading would call recent
	// (March 1 is after Feb 28) - is in fact still counted as old, because
	// the real threshold is March 3, not February 28.
	t.Run("end of month: Now=2026-08-31 rolls Feb 31 forward to March 3, not clamped to Feb 28", func(t *testing.T) {
		now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
		data := &audit.DetectorData{
			Now: now,
			Users: []types.User{
				{DN: "CN=krbtgt,CN=Users,DC=test,DC=local", SAMAccountName: "krbtgt", PasswordLastSet: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("password set March 1 must still be counted as old under the real March-3 threshold (would be 0 under a Feb-28-clamp reading), got count=%d", findings[0].Count)
		}
	})

	// Same mechanism, opposite month pairing: 2026-03-31 minus 6 months
	// lands on 2025-10-01 (verified live with `go run`), not on 2025-09-30.
	// A password set exactly on Sept 30 - which a "clamp to Sept 30" reading
	// would place ON the boundary (equal, not strictly before, so NOT
	// counted) - is in fact still counted, because the real threshold is
	// October 1, one full day later.
	t.Run("end of month: Now=2026-03-31 rolls Sept 31 forward to Oct 1, not clamped to Sept 30", func(t *testing.T) {
		now := time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC)
		data := &audit.DetectorData{
			Now: now,
			Users: []types.User{
				{DN: "CN=krbtgt,CN=Users,DC=test,DC=local", SAMAccountName: "krbtgt", PasswordLastSet: time.Date(2025, 9, 30, 0, 0, 0, 0, time.UTC)},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("password set Sept 30 must still be counted as old under the real Oct-1 threshold (would be 0 under a clamp-to-Sept-30 reading), got count=%d", findings[0].Count)
		}
	})

	// 180.5 days have elapsed, which a fixed-180-day reading of "6+ months"
	// would call old, but the code's actual 6-CALENDAR-MONTH threshold
	// (Dec 15, not reached until later) is not yet crossed, so this is NOT
	// counted - consistent with the calendar-month semantics the published
	// "6+ months" text now names. Verified with Python: Now=2026-06-15
	// minus 6 months = 2025-12-15T00:00:00Z; PasswordLastSet =
	// 2025-12-16T12:00:00Z is exactly 180.5 days before Now and falls AFTER
	// the threshold.
	t.Run("180.5 days elapsed but short of 6 calendar months -> NOT counted", func(t *testing.T) {
		now := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
		data := &audit.DetectorData{
			Now: now,
			Users: []types.User{
				{DN: "CN=krbtgt,CN=Users,DC=test,DC=local", SAMAccountName: "krbtgt", PasswordLastSet: time.Date(2025, 12, 16, 12, 0, 0, 0, time.UTC)},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("180.5 elapsed days must NOT be counted under the real 6-calendar-month code, got count=%d", findings[0].Count)
		}
	})

	t.Run("krbtgt absent: count 0, Description mentions unavailable date", func(t *testing.T) {
		now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
		data := &audit.DetectorData{
			Now: now,
			Users: []types.User{
				{DN: "CN=someone,CN=Users,DC=test,DC=local", SAMAccountName: "someone", PasswordLastSet: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("absent krbtgt must give count 0, got %d", findings[0].Count)
		}
		wantDesc := "krbtgt account password unchanged for 6+ months or password date unavailable. Enables persistent Golden Ticket attacks."
		if findings[0].Description != wantDesc {
			t.Fatalf("absent krbtgt must rewrite the Description to the unavailable-date variant, got %q, want %q", findings[0].Description, wantDesc)
		}
	})

	t.Run("krbtgt present but PasswordLastSet zero: count 0, Description mentions unavailable date", func(t *testing.T) {
		now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
		data := &audit.DetectorData{
			Now: now,
			Users: []types.User{
				{DN: "CN=krbtgt,CN=Users,DC=test,DC=local", SAMAccountName: "krbtgt"},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("zero PasswordLastSet must give count 0, got %d", findings[0].Count)
		}
		wantDesc := "krbtgt account password unchanged for 6+ months or password date unavailable. Enables persistent Golden Ticket attacks."
		if findings[0].Description != wantDesc {
			t.Fatalf("zero PasswordLastSet must rewrite the Description to the unavailable-date variant, got %q, want %q", findings[0].Description, wantDesc)
		}
	})

	// RODC krbtgt accounts are named krbtgt_<n> (e.g. krbtgt_12345), never
	// exactly "krbtgt". The exact-match comparison correctly excludes them:
	// the detector was never meant to (and per this ticket's scope, does
	// not) evaluate RODC krbtgt accounts.
	t.Run("only krbtgt_12345 (RODC) present, no plain krbtgt: count 0", func(t *testing.T) {
		now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
		data := &audit.DetectorData{
			Now: now,
			Users: []types.User{
				{DN: "CN=krbtgt_12345,CN=Users,DC=test,DC=local", SAMAccountName: "krbtgt_12345", PasswordLastSet: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("an RODC krbtgt_12345 account alone must not be matched as the domain krbtgt, got count=%d", findings[0].Count)
		}
	})

	// Documents real behavior: the comparison is case-sensitive, so an
	// account literally named "KRBTGT" (uppercase) is NOT matched even with
	// a very old password. AD's own directory is case-insensitive on
	// sAMAccountName uniqueness, so a coexisting "krbtgt" and "KRBTGT" pair
	// cannot exist on a real forest - this pins a defensive Go-level
	// behavior, not an exploitable real-world gap.
	t.Run("sAMAccountName KRBTGT (uppercase): NOT matched, count 0 (case-sensitive exact match)", func(t *testing.T) {
		now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
		data := &audit.DetectorData{
			Now: now,
			Users: []types.User{
				{DN: "CN=KRBTGT,CN=Users,DC=test,DC=local", SAMAccountName: "KRBTGT", PasswordLastSet: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("uppercase KRBTGT must not match the exact-case comparison, got count=%d", findings[0].Count)
		}
	})

	t.Run("IncludeDetails true: AffectedEntities populated", func(t *testing.T) {
		now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
		data := &audit.DetectorData{
			Now:            now,
			IncludeDetails: true,
			Users: []types.User{
				{DN: "CN=krbtgt,CN=Users,DC=test,DC=local", SAMAccountName: "krbtgt", PasswordLastSet: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
		}
		findings := d.Detect(context.Background(), data)
		if len(findings[0].AffectedEntities) != 1 {
			t.Fatalf("IncludeDetails=true must populate exactly 1 AffectedEntity, got %d", len(findings[0].AffectedEntities))
		}
	})

	t.Run("IncludeDetails false: AffectedEntities empty even though Count=1", func(t *testing.T) {
		now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
		data := &audit.DetectorData{
			Now:            now,
			IncludeDetails: false,
			Users: []types.User{
				{DN: "CN=krbtgt,CN=Users,DC=test,DC=local", SAMAccountName: "krbtgt", PasswordLastSet: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("Count must still be 1 regardless of IncludeDetails, got %d", findings[0].Count)
		}
		if len(findings[0].AffectedEntities) != 0 {
			t.Fatalf("IncludeDetails=false must leave AffectedEntities empty, got %d entities", len(findings[0].AffectedEntities))
		}
	})

	t.Run("Type stays GOLDEN_TICKET_RISK and Severity stays Critical", func(t *testing.T) {
		now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
		data := &audit.DetectorData{
			Now: now,
			Users: []types.User{
				{DN: "CN=krbtgt,CN=Users,DC=test,DC=local", SAMAccountName: "krbtgt", PasswordLastSet: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Type != "GOLDEN_TICKET_RISK" {
			t.Fatalf("Type must stay GOLDEN_TICKET_RISK, got %s", findings[0].Type)
		}
		if findings[0].Severity != types.SeverityCritical {
			t.Fatalf("Severity must stay Critical, got %s", findings[0].Severity)
		}
	})
}
