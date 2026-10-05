package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// disabledDescriptionCorpus mirrors domain-admin-description_test.go's
// corpus structure but uses its own literal strings, distinct from the
// active test's fixtures, so a regression specific to the disabled half
// cannot hide behind the active test still passing.
func disabledDescriptionCorpus() []types.User {
	return []types.User{
		// --- must fire: disabled with a matching keyword ---
		{SAMAccountName: "old.enterprise", Description: "Decommissioned Enterprise Admin, archived 2024", Disabled: true},
		{SAMAccountName: "old.administrator", Description: "Old administrator login, do not reuse", Disabled: true},
		{SAMAccountName: "old.privileged", Description: "Retired privileged batch account", Disabled: true},
		// --- must NOT fire: active account, same kind of keyword ---
		{SAMAccountName: "active.admin", Description: "Active admin account for helpdesk"},
		// --- must NOT fire: disabled account, no keyword ---
		{SAMAccountName: "disabled.clean", Description: "Deprovisioned 2023", Disabled: true},
		{SAMAccountName: "disabled.empty", Description: "", Disabled: true},
	}
}

var wantFlaggedDisabledDescription = []string{"old.enterprise", "old.administrator", "old.privileged"}

func detectDisabledDescription(t *testing.T, includeDetails bool) types.Finding {
	t.Helper()
	findings := NewDomainAdminInDescriptionOnDisabledAccountDetector().Detect(context.Background(), &audit.DetectorData{
		IncludeDetails: includeDetails,
		Users:          disabledDescriptionCorpus(),
	})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// TestDomainAdminInDescriptionOnDisabledAccount_FiresOnlyOnDisabledWithPattern
// is the non-regression guard for this half: only disabled accounts
// carrying a matching keyword are counted.
func TestDomainAdminInDescriptionOnDisabledAccount_FiresOnlyOnDisabledWithPattern(t *testing.T) {
	f := detectDisabledDescription(t, true)

	if f.Count != len(wantFlaggedDisabledDescription) {
		t.Fatalf("count = %d, want %d", f.Count, len(wantFlaggedDisabledDescription))
	}
	if f.Severity != types.SeverityLow {
		t.Errorf("severity = %q, want low", f.Severity)
	}
	if len(f.AffectedEntities) != len(wantFlaggedDisabledDescription) {
		t.Fatalf("entities = %d, want %d", len(f.AffectedEntities), len(wantFlaggedDisabledDescription))
	}

	got := make(map[string]bool, len(f.AffectedEntities))
	for _, e := range f.AffectedEntities {
		got[e.SAMAccountName] = true
	}
	for _, want := range wantFlaggedDisabledDescription {
		if !got[want] {
			t.Errorf("account %q is not flagged", want)
		}
	}
	for _, notWanted := range []string{"active.admin", "disabled.clean", "disabled.empty"} {
		if got[notWanted] {
			t.Errorf("account %q must not be flagged", notWanted)
		}
	}
}

// TestDomainAdminInDescriptionOnDisabledAccount_ExcludesActiveAccounts is the
// guard's mutation kill: an active account carrying the exact same keyword
// must not fire here - it is reported instead, at High, by
// DomainAdminDescriptionDetector.
func TestDomainAdminInDescriptionOnDisabledAccount_ExcludesActiveAccounts(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "active.only", Description: "Active Domain Admin rotation contact"},
		},
	}
	f := NewDomainAdminInDescriptionOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("an active account with a matching description must not fire in the disabled-account detector, got count=%d", f.Count)
	}
}

// TestDomainAdminInDescriptionOnDisabledAccount_EmptyDescriptionSkippedNotHalted
// covers this detector's own copy of the empty-description guard, and that
// it SKIPS the empty entry rather than halting evaluation of users that come
// after it in data.Users.
func TestDomainAdminInDescriptionOnDisabledAccount_EmptyDescriptionSkippedNotHalted(t *testing.T) {
	users := []types.User{
		{SAMAccountName: "before-empty", Description: "Retired privileged support account", Disabled: true},
		{SAMAccountName: "empty-desc", Description: "", Disabled: true},
		{SAMAccountName: "after-empty", Description: "Former Domain Admin backup contact", Disabled: true},
	}
	data := &audit.DetectorData{Users: users}
	f := NewDomainAdminInDescriptionOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 2 {
		t.Fatalf("Count = %d, want 2 (empty description must be skipped, not halt evaluation of later users)", f.Count)
	}
}

// TestDomainAdminInDescriptionOnDisabledAccount_CountMatchesAffectedEntitiesLength
// covers the decompte-des-entites case for this half: a disabled user whose
// description matches TWO keywords at once must be counted exactly ONCE.
func TestDomainAdminInDescriptionOnDisabledAccount_CountMatchesAffectedEntitiesLength(t *testing.T) {
	users := []types.User{
		{SAMAccountName: "match-two-patterns", Description: "Retired Privileged Administrator backup account", Disabled: true},
		{SAMAccountName: "no-match", Description: "Former helpdesk technician", Disabled: true},
	}
	data := &audit.DetectorData{Users: users, IncludeDetails: true}
	f := NewDomainAdminInDescriptionOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (match-two-patterns, deduplicated)", f.Count)
	}
	if len(f.AffectedEntities) != 1 {
		t.Fatalf("len(AffectedEntities) = %d, want 1 (must match Count exactly)", len(f.AffectedEntities))
	}
}

// TestDomainAdminInDescription_PartitionIsExhaustive covers both detectors
// together: an account with a matching keyword is counted by exactly one of
// the two - active or disabled - never both, never neither.
func TestDomainAdminInDescription_PartitionIsExhaustive(t *testing.T) {
	users := []types.User{
		{SAMAccountName: "active-match", Description: "Domain Admin rotation contact"},
		{SAMAccountName: "disabled-match", Description: "Domain Admin rotation contact", Disabled: true},
		{SAMAccountName: "active-clean", Description: "no sensitive terms here"},
		{SAMAccountName: "disabled-clean", Description: "no sensitive terms here", Disabled: true},
	}
	data := &audit.DetectorData{Users: users, IncludeDetails: true}

	active := NewDomainAdminDescriptionDetector().Detect(context.Background(), data)
	disabled := NewDomainAdminInDescriptionOnDisabledAccountDetector().Detect(context.Background(), data)

	if active[0].Count != 1 {
		t.Fatalf("active half: want 1 (active-match), got %d", active[0].Count)
	}
	if disabled[0].Count != 1 {
		t.Fatalf("disabled half: want 1 (disabled-match), got %d", disabled[0].Count)
	}
}
