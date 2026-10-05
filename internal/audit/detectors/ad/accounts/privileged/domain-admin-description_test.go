package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestDomainAdminDescription_EachKeywordMatchesOnce is the positive case per
// motif: one literal description per entry of sensitiveKeywords
// (domain-admin-description.go:24-30), each realistic enough that an admin
// could plausibly have written it.
func TestDomainAdminDescription_EachKeywordMatchesOnce(t *testing.T) {
	tests := []struct {
		name        string
		description string
	}{
		{"domain_admin", "Backup contact for the Domain Admin rotation, do not delete"},
		{"enterprise_admin", "Former Enterprise Admin, kept for reference only"},
		{"administrator", "Legacy administrator account, do not delete"},
		{"admin_account", "Shared admin account for the helpdesk team"},
		{"privileged", "privileged service account for nightly backups"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Users: []types.User{{SAMAccountName: "u-" + tt.name, Description: tt.description}},
			}
			f := NewDomainAdminDescriptionDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("Count = %d, want 1 for description %q", f.Count, tt.description)
			}
		})
	}
}

// TestDomainAdminDescription_NearMissWordNotMatched is the negative-proche
// case required by the ticket: "Administrative" contains the substring
// "admin" but, letter for letter, never becomes "administrator" ("administr"
// + "ative" vs "administr" + "ator" - they diverge at the 12th character), so
// none of the five patterns should fire.
func TestDomainAdminDescription_NearMissWordNotMatched(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "assistant", Description: "Administrative assistant to the regional director"}},
	}
	f := NewDomainAdminDescriptionDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf(`Count = %d, want 0 ("Administrative" contains "admin" but must not match "administrator")`, f.Count)
	}
}

// TestDomainAdminDescription_EmptyDescriptionSkippedNotHalted covers the
// empty-description guard (domain-admin-description.go:37-39) and, more
// importantly, that it SKIPS the empty entry rather than halting evaluation
// of the users that come after it in data.Users.
func TestDomainAdminDescription_EmptyDescriptionSkippedNotHalted(t *testing.T) {
	users := []types.User{
		{SAMAccountName: "before-empty", Description: "privileged support account"},
		{SAMAccountName: "empty-desc", Description: ""},
		{SAMAccountName: "after-empty", Description: "Domain Admin backup contact"},
	}
	data := &audit.DetectorData{Users: users}
	f := NewDomainAdminDescriptionDetector().Detect(context.Background(), data)[0]
	if f.Count != 2 {
		t.Fatalf("Count = %d, want 2 (empty description must be skipped, not halt evaluation of later users)", f.Count)
	}
}

// TestDomainAdminDescription_CaseInsensitivePrivilegedMatches covers the
// case-insensitivity of the "privileged" pattern in isolation: an
// upper-case description that contains no other sensitive keyword (unlike
// "Administrator", which would mask this specific pattern's own
// case-insensitivity).
func TestDomainAdminDescription_CaseInsensitivePrivilegedMatches(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "u-upper", Description: "PRIVILEGED SERVICE ACCOUNT FOR NIGHTLY BACKUPS"}},
	}
	f := NewDomainAdminDescriptionDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (uppercase PRIVILEGED must still match case-insensitively)", f.Count)
	}
}

// TestDomainAdminDescription_FlexibleWhitespaceInDomainAdmin covers the
// \s* in the domain-admin pattern: it must match zero whitespace
// characters (glued "DomainAdmin") as well as more than one (double space
// "Domain  Admin"), not just the single space used by the earlier
// EachKeywordMatchesOnce case.
func TestDomainAdminDescription_FlexibleWhitespaceInDomainAdmin(t *testing.T) {
	tests := []struct {
		name        string
		description string
	}{
		{"no_space", "Legacy DomainAdmin credentials, keep for reference"},
		{"double_space", "Legacy Domain  Admin credentials, keep for reference"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Users: []types.User{{SAMAccountName: "u-" + tt.name, Description: tt.description}},
			}
			f := NewDomainAdminDescriptionDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("Count = %d, want 1 for description %q", f.Count, tt.description)
			}
		})
	}
}

// TestDomainAdminDescription_CountMatchesAffectedEntitiesLength is the
// decompte-des-entites case: a user whose description matches TWO patterns
// at once ("Privileged Administrator backup account" hits both
// "administrator" and "privileged") must be counted exactly ONCE - Count and
// len(AffectedEntities) must both equal the number of DISTINCT matching
// users, never the number of pattern hits.
func TestDomainAdminDescription_CountMatchesAffectedEntitiesLength(t *testing.T) {
	users := []types.User{
		{SAMAccountName: "match-one", Description: "privileged support account"},
		{SAMAccountName: "match-two-patterns", Description: "Privileged Administrator backup account"},
		{SAMAccountName: "no-match", Description: "Regular helpdesk technician"},
		{SAMAccountName: "empty", Description: ""},
	}
	data := &audit.DetectorData{Users: users, IncludeDetails: true}
	f := NewDomainAdminDescriptionDetector().Detect(context.Background(), data)[0]
	if f.Count != 2 {
		t.Fatalf("Count = %d, want 2 (exactly match-one and match-two-patterns, deduplicated)", f.Count)
	}
	if len(f.AffectedEntities) != 2 {
		t.Fatalf("len(AffectedEntities) = %d, want 2 (must match Count exactly)", len(f.AffectedEntities))
	}
}

// TestDomainAdminDescription_ExcludesDisabledAccounts covers the guard added
// by the split: a disabled account carrying the exact same keyword as a live
// true positive must not fire here anymore - it is reported instead, at Low,
// by DomainAdminInDescriptionOnDisabledAccountDetector.
func TestDomainAdminDescription_ExcludesDisabledAccounts(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "disabled.admin", Description: "Former Domain Admin, kept for reference", Disabled: true},
		},
	}
	f := NewDomainAdminDescriptionDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("a disabled account with a matching description must not fire in the active detector, got count=%d", f.Count)
	}
}
