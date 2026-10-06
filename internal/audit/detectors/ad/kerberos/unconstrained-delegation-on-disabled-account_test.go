package kerberos

import (
	"context"
	"regexp"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// reUnconstrainedDelegationRefutedClaim matches the phrases the KDC
// measurement in
// docs/security-validation/results/unconstrained-delegation-disabled-v2/VERDICT.md,
// its independent verification
// docs/security-validation/verifications/unconstrained-delegation-disabled-v2/VERDICT-security.md,
// and the follow-on computer-account measurement in
// docs/security-validation/results/computer-unconstrained-delegation-disabled-v2/VERDICT.md
// refuted: a disabled account's SPN never gets a service ticket from the
// KDC, so it cannot "work the same as against an active" account or "remain
// a valid delegation target" - the KDC very much does revalidate the
// target's enabled state, "regardless of account status" notwithstanding.
var reUnconstrainedDelegationRefutedClaim = regexp.MustCompile(`\bnever revalidates\b|\bdoes not revalidate\b|\bregardless of account status\b|\bremains a valid delegation target\b|\bworks the same as against an active\b`)

// reUnconstrainedDelegationClientErrorCode guards against a client-specific
// error code leaking into shipped text: the raw codes belong in a VERDICT,
// where the full measurement context (which client, which OS build) makes
// them meaningful, not in text a reader sees with no such context attached.
var reUnconstrainedDelegationClientErrorCode = regexp.MustCompile(`\b0x6fb\b|\b0xc000018b\b|\bERROR_[A-Z_]+\b|\bSTATUS_[A-Z_]+\b|\bKDC_ERR_[A-Z_]+\b|\b1331\b`)

// reUnconstrainedDelegationTicketGrantingTicketWord and
// reUnconstrainedDelegationServiceTicketWord together require the Description
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
var reUnconstrainedDelegationTicketGrantingTicketWord = regexp.MustCompile(`\bticket-granting ticket\b`)
var reUnconstrainedDelegationServiceTicketWord = regexp.MustCompile(`\bservice ticket\b`)

func TestUnconstrainedDelegationOnDisabledAccount(t *testing.T) {
	userDN := "CN=svc,OU=Services,DC=test,DC=local"

	t.Run("disabled account with the bit fires here", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, UserAccountControl: types.UACTrustedForDelegation},
			},
			IncludeDetails: true,
		}
		findings := NewUnconstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 1 {
			t.Fatalf("disabled account with the bit must fire here, got %+v", findings)
		}
		if findings[0].Severity != types.SeverityLow {
			t.Fatalf("disabled half must be Low (KDC refuses a service ticket for a disabled account's SPN, measured against a real KDC - see docs/security-validation/results/unconstrained-delegation-disabled-v2/VERDICT.md), got %s", findings[0].Severity)
		}
	})

	t.Run("active account does NOT fire here, even with the bit", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", UserAccountControl: types.UACTrustedForDelegation},
			},
		}
		findings := NewUnconstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("active accounts must not be counted by the disabled-account detector, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled account without the bit does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{{DN: userDN, SAMAccountName: "svc", Disabled: true}},
		}
		findings := NewUnconstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("a disabled account without the bit must not fire, got count=%d", findings[0].Count)
		}
	})

	// SPN presence or absence does not change whether this half fires, and -
	// since the KDC measurement in
	// docs/security-validation/results/unconstrained-delegation-disabled-v2/VERDICT.md
	// found both populations equally inert while the account stays disabled -
	// it no longer changes what the finding means either. Severity/weight
	// stay attached to the type, not the individual object, per this
	// catalog's standing rule.
	t.Run("SPN presence or absence does not change whether this half fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "with-spn", Disabled: true, UserAccountControl: types.UACTrustedForDelegation, ServicePrincipalNames: []string{"CIFS/svc.test.local", "MSSQL/svc.test.local:1433"}},
				{DN: userDN, SAMAccountName: "without-spn", Disabled: true, UserAccountControl: types.UACTrustedForDelegation},
			},
		}
		findings := NewUnconstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 2 {
			t.Fatalf("SPN presence must not affect the current condition, got count=%d", findings[0].Count)
		}
	})
}

// TestUnconstrainedDelegationOnDisabledAccount_DescriptionDropsRefutedClaim
// guards the Description string returned by Detect(). Mutation M1: put the
// phrase "the KDC never revalidates the target's enabled state during the
// TGS exchange" back into the Description literal in
// unconstrained-delegation-on-disabled-account.go and this test goes red.
func TestUnconstrainedDelegationOnDisabledAccount_DescriptionDropsRefutedClaim(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc,OU=Services,DC=test,DC=local", SAMAccountName: "svc", Disabled: true, UserAccountControl: types.UACTrustedForDelegation},
		},
	}
	findings := NewUnconstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
	if reUnconstrainedDelegationRefutedClaim.MatchString(findings[0].Description) {
		t.Fatalf("Description still asserts the refuted KDC claim: %q", findings[0].Description)
	}
}

// TestUnconstrainedDelegationOnDisabledAccount_DocDropsRefutedClaim guards
// Doc().Description independently of Detect()'s Description: the catalog
// text is a separate copy (docs_gen.go), not test-coupled to the runtime
// string by the Go compiler. Mutation M2: put the refuted phrase back into
// docs_gen.go's Doc() literal for this detector and this test goes red.
func TestUnconstrainedDelegationOnDisabledAccount_DocDropsRefutedClaim(t *testing.T) {
	doc := NewUnconstrainedDelegationOnDisabledAccountDetector().Doc()
	if reUnconstrainedDelegationRefutedClaim.MatchString(doc.Description) {
		t.Fatalf("Doc().Description still asserts the refuted KDC claim: %q", doc.Description)
	}
	if reUnconstrainedDelegationClientErrorCode.MatchString(doc.Description) {
		t.Fatalf("Doc().Description carries a client-specific error code: %q", doc.Description)
	}
}

// TestUnconstrainedDelegationOnDisabledAccount_DescriptionNoClientErrorCode
// guards against a client-specific error code (meaningful only inside a
// VERDICT that names the client and OS build) leaking into shipped text.
// Mutation M3: append "(0x6fb/0xc000018b)" to the Description literal and
// this test goes red.
func TestUnconstrainedDelegationOnDisabledAccount_DescriptionNoClientErrorCode(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc,OU=Services,DC=test,DC=local", SAMAccountName: "svc", Disabled: true, UserAccountControl: types.UACTrustedForDelegation},
		},
	}
	findings := NewUnconstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
	if reUnconstrainedDelegationClientErrorCode.MatchString(findings[0].Description) {
		t.Fatalf("Description carries a client-specific error code: %q", findings[0].Description)
	}
}

// TestUnconstrainedDelegationOnDisabledAccount_DescriptionAffirmsBothRefusals
// guards the POSITIVE claim: dropping the retired phrases is not enough if a
// paraphrase of the same falsehood takes their place. Mutation M7: replace
// the Description literal with a paraphrase that restates the refuted claim
// without using any retired phrase (e.g. "a coerced authentication against
// this account's SPN succeeds identically whether the account is active or
// disabled") and this test goes red, because "ticket-granting ticket" and
// "service ticket" both disappear along with the true claim.
func TestUnconstrainedDelegationOnDisabledAccount_DescriptionAffirmsBothRefusals(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc,OU=Services,DC=test,DC=local", SAMAccountName: "svc", Disabled: true, UserAccountControl: types.UACTrustedForDelegation},
		},
	}
	findings := NewUnconstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
	d := findings[0].Description
	if !reUnconstrainedDelegationTicketGrantingTicketWord.MatchString(d) || !reUnconstrainedDelegationServiceTicketWord.MatchString(d) {
		t.Fatalf("Description no longer positively states both KDC refusals (ticket-granting ticket, service ticket): %q", d)
	}
}

// TestUnconstrainedDelegationOnDisabledAccount_DocAffirmsBothRefusals is the
// Doc()-only counterpart: docs_gen.go is a separate copy, not test-coupled to
// Detect()'s Description by the Go compiler. Mutation M8: apply the same
// paraphrase to docs_gen.go's Doc() literal alone (Detect()'s Description
// stays correct) and this test goes red while
// TestUnconstrainedDelegationOnDisabledAccount_DescriptionAffirmsBothRefusals
// stays green - proving the two guards are independent.
func TestUnconstrainedDelegationOnDisabledAccount_DocAffirmsBothRefusals(t *testing.T) {
	doc := NewUnconstrainedDelegationOnDisabledAccountDetector().Doc()
	if !reUnconstrainedDelegationTicketGrantingTicketWord.MatchString(doc.Description) || !reUnconstrainedDelegationServiceTicketWord.MatchString(doc.Description) {
		t.Fatalf("Doc().Description no longer positively states both KDC refusals (ticket-granting ticket, service ticket): %q", doc.Description)
	}
}
