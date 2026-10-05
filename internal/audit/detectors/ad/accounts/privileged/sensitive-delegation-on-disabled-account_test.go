package privileged

import (
	"context"
	"regexp"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// reSensitiveDelegationRefutedClaim matches the phrases the KDC measurement
// in
// docs/security-validation/results/unconstrained-delegation-disabled-v2/VERDICT.md,
// its independent verification
// docs/security-validation/verifications/unconstrained-delegation-disabled-v2/VERDICT-security.md,
// and the follow-on computer-account measurement in
// docs/security-validation/results/computer-unconstrained-delegation-disabled-v2/VERDICT.md
// refuted for this detector too: a disabled account's SPN never gets a
// service ticket from the KDC, so it cannot "work the same as against an
// active" account or "remain a valid delegation target" - the KDC very much
// does revalidate the target's enabled state, "regardless of account status"
// notwithstanding.
var reSensitiveDelegationRefutedClaim = regexp.MustCompile(`\bnever revalidates\b|\bdoes not revalidate\b|\bregardless of account status\b|\bremains a valid delegation target\b|\bworks the same as against an active\b`)

// reSensitiveDelegationClientErrorCode guards against a client-specific error
// code leaking into shipped text: the raw codes belong in a VERDICT, where
// the full measurement context (which client, which OS build) makes them
// meaningful, not in text a reader sees with no such context attached.
var reSensitiveDelegationClientErrorCode = regexp.MustCompile(`\b0x6fb\b|\b0xc000018b\b|\bERROR_[A-Z_]+\b|\bSTATUS_[A-Z_]+\b|\bKDC_ERR_[A-Z_]+\b|\b1331\b`)

// reSensitiveDelegationTicketGrantingTicketWord and
// reSensitiveDelegationServiceTicketWord together require the Description
// and Doc() to POSITIVELY state both measured refusals - the account cannot
// get a ticket-granting ticket of its own (closing the delegation-origin
// role) and the KDC will not issue a service ticket for its SPN (closing the
// delegation-target role) - not just avoid the retired phrases above. A
// negative-only guard lets a paraphrase of the refuted claim through as long
// as it dodges those exact phrases - e.g. "a coerced authentication against
// this account's SPN succeeds identically whether the account is active or
// disabled" restates the same falsehood in different words and matches none
// of them. Requiring both true claims in positive terms closes that gap: if
// a paraphrase (true or false) replaces the actual claim, these words
// disappear and the test goes red regardless of what replaced them.
var reSensitiveDelegationTicketGrantingTicketWord = regexp.MustCompile(`\bticket-granting ticket\b`)
var reSensitiveDelegationServiceTicketWord = regexp.MustCompile(`\bservice ticket\b`)

// TestSensitiveDelegationOnDisabledAccount_EnabledAccountExcluded is the
// mirror of TestSensitiveDelegation_DisabledAccountExcluded: an enabled
// privileged account with the delegation bit belongs to
// SensitiveDelegationDetector (Critical), not here.
func TestSensitiveDelegationOnDisabledAccount_EnabledAccountExcluded(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		ObjectBySID:    objectBySIDWithGroup(daSID, daDN),
		Users: []types.User{
			{
				SAMAccountName:     "active-da",
				UserAccountControl: types.UACTrustedForDelegation,
				Disabled:           false,
				MemberOf:           []string{daDN},
			},
			{
				SAMAccountName:     "stale-da",
				UserAccountControl: types.UACTrustedForDelegation,
				Disabled:           true,
				MemberOf:           []string{daDN},
			},
		},
	}

	findings := NewSensitiveDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (enabled account must be excluded)", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityLow {
		t.Fatalf("Severity = %s, want low (the KDC refuses a service ticket for a disabled account's SPN, measured against a real KDC - see docs/security-validation/results/unconstrained-delegation-disabled-v2/VERDICT.md - so the privileged target role is dormant too while the account stays disabled)", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "stale-da" {
		t.Fatalf("AffectedEntities = %+v, want only stale-da", findings[0].AffectedEntities)
	}
}

// TestSensitiveDelegationOnDisabledAccount_NotPrivilegedNotFlagged guards the
// negative case for the disabled-account half.
func TestSensitiveDelegationOnDisabledAccount_NotPrivilegedNotFlagged(t *testing.T) {
	ordinaryDN := "CN=GS-Employees,OU=Groups,DC=example,DC=com"
	data := &audit.DetectorData{
		ObjectBySID: objectBySIDWithGroup("S-1-5-21-1111111111-2222222222-3333333333-9001", ordinaryDN),
		Users: []types.User{
			{
				SAMAccountName:     "ordinary-disabled",
				UserAccountControl: types.UACTrustedForDelegation,
				Disabled:           true,
				MemberOf:           []string{ordinaryDN},
			},
		},
	}

	findings := NewSensitiveDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestSensitiveDelegationOnDisabledAccount_WidenedCoverageBySuffix mirrors
// TestSensitiveDelegation_WidenedCoverageBySuffix on the disabled-account
// half: Account Operators (RID -548) is now covered here too, at Low.
func TestSensitiveDelegationOnDisabledAccount_WidenedCoverageBySuffix(t *testing.T) {
	aoDN := "CN=Account Operators,CN=Builtin,DC=example,DC=com"
	aoSID := "S-1-5-21-1111111111-2222222222-3333333333-548"
	data := &audit.DetectorData{
		IncludeDetails: true,
		ObjectBySID:    objectBySIDWithGroup(aoSID, aoDN),
		Users: []types.User{
			{
				SAMAccountName:     "ao-member-disabled",
				UserAccountControl: types.UACTrustedForDelegation,
				Disabled:           true,
				MemberOf:           []string{aoDN},
			},
		},
	}

	findings := NewSensitiveDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (Account Operators is now covered by RID suffix -548)", findings[0].Count)
	}
}

// TestSensitiveDelegationOnDisabledAccount_DescriptionDropsRefutedClaim
// guards the Description string returned by Detect(). Mutation M1: put the
// phrase "the KDC never revalidates the target's enabled state during the
// TGS exchange" back into the Description literal in
// sensitive-delegation-on-disabled-account.go and this test goes red.
func TestSensitiveDelegationOnDisabledAccount_DescriptionDropsRefutedClaim(t *testing.T) {
	data := &audit.DetectorData{
		ObjectBySID: objectBySIDWithGroup(daSID, daDN),
		Users: []types.User{
			{
				SAMAccountName:     "stale-da",
				UserAccountControl: types.UACTrustedForDelegation,
				Disabled:           true,
				MemberOf:           []string{daDN},
			},
		},
	}
	findings := NewSensitiveDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
	if reSensitiveDelegationRefutedClaim.MatchString(findings[0].Description) {
		t.Fatalf("Description still asserts the refuted KDC claim: %q", findings[0].Description)
	}
}

// TestSensitiveDelegationOnDisabledAccount_DocDropsRefutedClaim guards
// Doc().Description independently of Detect()'s Description: the catalog
// text is a separate copy (docs_gen.go), not test-coupled to the runtime
// string by the Go compiler. Mutation M2: put the refuted phrase back into
// docs_gen.go's Doc() literal for this detector and this test goes red.
func TestSensitiveDelegationOnDisabledAccount_DocDropsRefutedClaim(t *testing.T) {
	doc := NewSensitiveDelegationOnDisabledAccountDetector().Doc()
	if reSensitiveDelegationRefutedClaim.MatchString(doc.Description) {
		t.Fatalf("Doc().Description still asserts the refuted KDC claim: %q", doc.Description)
	}
	if reSensitiveDelegationClientErrorCode.MatchString(doc.Description) {
		t.Fatalf("Doc().Description carries a client-specific error code: %q", doc.Description)
	}
}

// TestSensitiveDelegationOnDisabledAccount_DescriptionNoClientErrorCode
// guards against a client-specific error code (meaningful only inside a
// VERDICT that names the client and OS build) leaking into shipped text.
// Mutation M3: append "(0x6fb/0xc000018b)" to the Description literal and
// this test goes red.
func TestSensitiveDelegationOnDisabledAccount_DescriptionNoClientErrorCode(t *testing.T) {
	data := &audit.DetectorData{
		ObjectBySID: objectBySIDWithGroup(daSID, daDN),
		Users: []types.User{
			{
				SAMAccountName:     "stale-da",
				UserAccountControl: types.UACTrustedForDelegation,
				Disabled:           true,
				MemberOf:           []string{daDN},
			},
		},
	}
	findings := NewSensitiveDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
	if reSensitiveDelegationClientErrorCode.MatchString(findings[0].Description) {
		t.Fatalf("Description carries a client-specific error code: %q", findings[0].Description)
	}
}

// TestSensitiveDelegationOnDisabledAccount_DescriptionAffirmsBothRefusals
// guards the POSITIVE claim: dropping the retired phrases is not enough if a
// paraphrase of the same falsehood takes their place. Mutation M9: replace
// the Description literal with a paraphrase that restates the refuted claim
// without using any retired phrase (e.g. "a coerced authentication against
// this account's SPN succeeds identically whether the account is active or
// disabled") and this test goes red, because "ticket-granting ticket" and
// "service ticket" both disappear along with the true claim.
func TestSensitiveDelegationOnDisabledAccount_DescriptionAffirmsBothRefusals(t *testing.T) {
	data := &audit.DetectorData{
		ObjectBySID: objectBySIDWithGroup(daSID, daDN),
		Users: []types.User{
			{
				SAMAccountName:     "stale-da",
				UserAccountControl: types.UACTrustedForDelegation,
				Disabled:           true,
				MemberOf:           []string{daDN},
			},
		},
	}
	findings := NewSensitiveDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
	d := findings[0].Description
	if !reSensitiveDelegationTicketGrantingTicketWord.MatchString(d) || !reSensitiveDelegationServiceTicketWord.MatchString(d) {
		t.Fatalf("Description no longer positively states both KDC refusals (ticket-granting ticket, service ticket): %q", d)
	}
}

// TestSensitiveDelegationOnDisabledAccount_DocAffirmsBothRefusals is the
// Doc()-only counterpart: docs_gen.go is a separate copy, not test-coupled to
// Detect()'s Description by the Go compiler. Mutation M10: apply the same
// paraphrase to docs_gen.go's Doc() literal alone (Detect()'s Description
// stays correct) and this test goes red while
// TestSensitiveDelegationOnDisabledAccount_DescriptionAffirmsBothRefusals
// stays green - proving the two guards are independent.
func TestSensitiveDelegationOnDisabledAccount_DocAffirmsBothRefusals(t *testing.T) {
	doc := NewSensitiveDelegationOnDisabledAccountDetector().Doc()
	if !reSensitiveDelegationTicketGrantingTicketWord.MatchString(doc.Description) || !reSensitiveDelegationServiceTicketWord.MatchString(doc.Description) {
		t.Fatalf("Doc().Description no longer positively states both KDC refusals (ticket-granting ticket, service ticket): %q", doc.Description)
	}
}
