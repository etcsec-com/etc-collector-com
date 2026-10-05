package delegation

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// reComputerDelegationActiveTextGuard guards THIS ACTIVE (Critical)
// detector's text against reintroducing disabled accounts as covered: the
// bare word "disabled", and the specific formulas the KDC measurement in
// docs/security-validation/results/computer-unconstrained-delegation-disabled-v2/VERDICT.md
// refuted (a disabled computer account is neither a valid delegation origin
// nor target, and the KDC does check the account's enabled state on both the
// TGT and the service-ticket path). Deliberately NOT the same regex as
// reComputerDelegationRefutedClaim above and NOT shared with
// unconstrained-delegation-on-disabled-account_test.go: that detector's own
// Description legitimately talks about disabled accounts, so a bare
// "disabled" match would misfire there.
var reComputerDelegationActiveTextGuard = regexp.MustCompile(`(?i)\bdisabled\b|\bnever revalidates\b|\bnever checks\b|\bdoes not revalidate\b|\bregardless of account status\b|\bremains a valid delegation target\b|\bwhether enabled or disabled\b`)

// reComputerDelegationRefutedClaim matches the phrases the KDC measurement in
// docs/security-validation/results/computer-unconstrained-delegation-disabled-v2/VERDICT.md
// refuted: a disabled computer account's SPN never gets a service ticket from
// the KDC, so it cannot "work the same as against an active" account or
// "remain a valid delegation target" - the KDC very much does revalidate the
// target's enabled state, "regardless of account status" notwithstanding.
// Shared with unconstrained-delegation-on-disabled-account_test.go (same
// package).
var reComputerDelegationRefutedClaim = regexp.MustCompile(`\bnever revalidates\b|\bdoes not revalidate\b|\bregardless of account status\b|\bremains a valid delegation target\b|\bworks the same as against an active\b`)

// reComputerDelegationClientErrorCode guards against a client-specific error
// code leaking into shipped text: the raw codes belong in a VERDICT, where
// the full measurement context (which client, which OS build) makes them
// meaningful, not in text a reader sees with no such context attached.
var reComputerDelegationClientErrorCode = regexp.MustCompile(`\b0x6fb\b|\b0xc000018b\b|\bERROR_[A-Z_]+\b|\bSTATUS_[A-Z_]+\b|\bKDC_ERR_[A-Z_]+\b|\b1331\b`)

// reComputerDelegationTicketGrantingTicketWord and
// reComputerDelegationServiceTicketWord together require the disabled-account
// detector's Description and Doc() to POSITIVELY state both measured
// refusals. Not used by this file's own guard test (the active/Critical
// detector's text does not narrate a KDC refusal at all), but shared here so
// both computers/delegation test files draw from one definition.
var reComputerDelegationTicketGrantingTicketWord = regexp.MustCompile(`\bticket-granting ticket\b`)
var reComputerDelegationServiceTicketWord = regexp.MustCompile(`\bservice ticket\b`)

// Microsoft Defender for Identity explicitly excludes domain
// controllers from its "Unsecure Kerberos delegation" assessment: every DC
// carries unconstrained delegation by design, so flagging it is not a
// finding. The prior version of this detector flagged every DC in every
// domain as Critical.
func TestUnconstrainedDelegation_DomainControllersExcluded(t *testing.T) {
	const domainDN = "DC=example,DC=com"

	dc := types.Computer{
		DN:                   "CN=DC01,OU=Domain Controllers," + domainDN,
		SAMAccountName:       "DC01$",
		TrustedForDelegation: true,
		UserAccountControl:   0x2000, // SERVER_TRUST_ACCOUNT | unconstrained delegation flag would also be set on real DCs
	}
	member := types.Computer{
		DN:                   "CN=APPSRV01,OU=Servers," + domainDN,
		SAMAccountName:       "APPSRV01$",
		TrustedForDelegation: true,
	}

	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers:      []types.Computer{dc, member},
	}

	findings := NewUnconstrainedDelegationDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (only the member server, not the DC)", f.Count)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].DN != member.DN {
		t.Fatalf("AffectedEntities = %v, want only %q", f.AffectedEntities, member.DN)
	}
}

// A disabled computer account is now excluded, on the same model as the
// user-account pair in ad/kerberos
// (UnconstrainedDelegationOnDisabledAccountDetector) and the
// privileged-account pair in ad/accounts/privileged
// (SensitiveDelegationOnDisabledAccountDetector): measured directly against a
// live KDC, a disabled computer account carrying a registered SPN still gets
// no service ticket for it - see
// docs/security-validation/results/computer-unconstrained-delegation-disabled-v2/VERDICT.md.
// That population is reported separately, at Low, by
// UnconstrainedDelegationOnDisabledAccountDetector in this same package.
func TestUnconstrainedDelegation_DisabledComputerExcluded(t *testing.T) {
	const domainDN = "DC=example,DC=com"

	disabled := types.Computer{
		DN:                    "CN=SVR01,OU=Servers," + domainDN,
		SAMAccountName:        "SVR01$",
		TrustedForDelegation:  true,
		Disabled:              true,
		ServicePrincipalNames: []string{"HOST/svr01.example.com"},
	}

	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers:      []types.Computer{disabled},
	}

	findings := NewUnconstrainedDelegationDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 - a disabled computer account must be excluded from the active/Critical detector, even with a registered SPN and the bit set", f.Count)
	}
}

// TestUnconstrainedDelegation_DescriptionDropsRefutedClaim guards the
// Description string returned by Detect(). Mutation M4: put the phrase
// "regardless of account status: a disabled computer account remains a valid
// delegation target" back into the Description literal in
// unconstrained-delegation.go and this test goes red.
func TestUnconstrainedDelegation_DescriptionDropsRefutedClaim(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=SVR01,OU=Servers,DC=example,DC=com", SAMAccountName: "SVR01$", TrustedForDelegation: true},
		},
	}
	findings := NewUnconstrainedDelegationDetector().Detect(context.Background(), data)
	if reComputerDelegationRefutedClaim.MatchString(findings[0].Description) {
		t.Fatalf("Description still asserts the refuted KDC claim: %q", findings[0].Description)
	}
	if reComputerDelegationClientErrorCode.MatchString(findings[0].Description) {
		t.Fatalf("Description carries a client-specific error code: %q", findings[0].Description)
	}
}

// TestUnconstrainedDelegation_DocDropsRefutedClaim guards Doc().Description
// independently of Detect()'s Description: the catalog text is a separate
// copy (docs_gen.go), not test-coupled to the runtime string by the Go
// compiler. Mutation M5: put the refuted phrase back into docs_gen.go's
// Doc() literal for this detector and this test goes red.
func TestUnconstrainedDelegation_DocDropsRefutedClaim(t *testing.T) {
	doc := NewUnconstrainedDelegationDetector().Doc()
	if reComputerDelegationRefutedClaim.MatchString(doc.Description) {
		t.Fatalf("Doc().Description still asserts the refuted KDC claim: %q", doc.Description)
	}
	if reComputerDelegationClientErrorCode.MatchString(doc.Description) {
		t.Fatalf("Doc().Description carries a client-specific error code: %q", doc.Description)
	}
}

// TestUnconstrainedDelegation_DescriptionNoDisabledLanguage guards the
// Description string returned by Detect(): this active/Critical detector's
// text must never claim to cover disabled accounts.
func TestUnconstrainedDelegation_DescriptionNoDisabledLanguage(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=SVR01,OU=Servers,DC=example,DC=com", SAMAccountName: "SVR01$", TrustedForDelegation: true},
		},
	}
	findings := NewUnconstrainedDelegationDetector().Detect(context.Background(), data)
	if reComputerDelegationActiveTextGuard.MatchString(findings[0].Description) {
		t.Fatalf("Description must not mention disabled accounts or a refuted KDC claim: %q", findings[0].Description)
	}
}

// TestUnconstrainedDelegation_DocNoDisabledLanguage is the Doc()-only
// counterpart: docs_gen.go is a separate copy, not test-coupled to Detect()'s
// Description by the Go compiler.
func TestUnconstrainedDelegation_DocNoDisabledLanguage(t *testing.T) {
	doc := NewUnconstrainedDelegationDetector().Doc()
	if reComputerDelegationActiveTextGuard.MatchString(doc.Description) {
		t.Fatalf("Doc().Description must not mention disabled accounts or a refuted KDC claim: %q", doc.Description)
	}
}

// TestUnconstrainedDelegation_DescriptionStartsWithEnabled guards the
// positive claim: the text must open by naming the population it actually
// covers.
func TestUnconstrainedDelegation_DescriptionStartsWithEnabled(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=SVR01,OU=Servers,DC=example,DC=com", SAMAccountName: "SVR01$", TrustedForDelegation: true},
		},
	}
	findings := NewUnconstrainedDelegationDetector().Detect(context.Background(), data)
	if !strings.HasPrefix(findings[0].Description, "Enabled") {
		t.Fatalf("Description must start with %q, got %q", "Enabled", findings[0].Description)
	}
}

// TestUnconstrainedDelegation_DocStartsWithEnabled is the Doc()-only
// counterpart of TestUnconstrainedDelegation_DescriptionStartsWithEnabled.
func TestUnconstrainedDelegation_DocStartsWithEnabled(t *testing.T) {
	doc := NewUnconstrainedDelegationDetector().Doc()
	if !strings.HasPrefix(doc.Description, "Enabled") {
		t.Fatalf("Doc().Description must start with %q, got %q", "Enabled", doc.Description)
	}
}
