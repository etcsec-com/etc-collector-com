package delegation

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestComputerUnconstrainedDelegationPartition checks that the active
// (Critical) and disabled-account (Low) detectors partition the same
// population: every computer lands in exactly one of them, or neither, never
// both. UAC values are literal combinations distinct from the bare
// types.UACTrustedForDelegation / uacServerTrustAccount constants, matching
// the shape seen on a real lab-issued computer account (WORKSTATION_TRUST_ACCOUNT
// 0x1000 | TRUSTED_FOR_DELEGATION 0x80000 = 0x81000, plus ACCOUNTDISABLE 0x2
// or SERVER_TRUST_ACCOUNT 0x2000 as needed) rather than the single named bit
// each detector actually tests.
func TestComputerUnconstrainedDelegationPartition(t *testing.T) {
	cases := []struct {
		name         string
		computer     types.Computer
		wantCritical int
		wantLow      int
	}{
		{
			name: "active non-DC computer with the bit fires Critical only",
			computer: types.Computer{
				DN: "CN=APPSRV01,OU=Servers,DC=example,DC=com", SAMAccountName: "APPSRV01$",
				TrustedForDelegation: true, Disabled: false, UserAccountControl: 0x81000,
			},
			wantCritical: 1, wantLow: 0,
		},
		{
			name: "disabled non-DC computer with the bit fires the disabled-account detector only",
			computer: types.Computer{
				DN: "CN=SVR02,OU=Servers,DC=example,DC=com", SAMAccountName: "SVR02$",
				TrustedForDelegation: true, Disabled: true, UserAccountControl: 0x81002,
			},
			wantCritical: 0, wantLow: 1,
		},
		{
			name: "domain controller with the bit fires neither, even if disabled",
			computer: types.Computer{
				DN: "CN=DC03,OU=Domain Controllers,DC=example,DC=com", SAMAccountName: "DC03$",
				TrustedForDelegation: true, Disabled: true, UserAccountControl: 0x82002,
			},
			wantCritical: 0, wantLow: 0,
		},
		{
			name: "active non-DC computer without the bit fires neither",
			computer: types.Computer{
				DN: "CN=WKS01,OU=Workstations,DC=example,DC=com", SAMAccountName: "WKS01$",
				TrustedForDelegation: false, Disabled: false, UserAccountControl: 0x1000,
			},
			wantCritical: 0, wantLow: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{Computers: []types.Computer{tc.computer}}

			critical := NewUnconstrainedDelegationDetector().Detect(context.Background(), data)
			if critical[0].Count != tc.wantCritical {
				t.Fatalf("COMPUTER_UNCONSTRAINED_DELEGATION Count = %d, want %d", critical[0].Count, tc.wantCritical)
			}

			low := NewUnconstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
			if low[0].Count != tc.wantLow {
				t.Fatalf("COMPUTER_UNCONSTRAINED_DELEGATION_ON_DISABLED_ACCOUNT Count = %d, want %d", low[0].Count, tc.wantLow)
			}
		})
	}
}

func TestUnconstrainedDelegationOnDisabledAccount_SeverityIsLow(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=SVR02,OU=Servers,DC=example,DC=com", SAMAccountName: "SVR02$", TrustedForDelegation: true, Disabled: true},
		},
	}
	findings := NewUnconstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Severity != types.SeverityLow {
		t.Fatalf("Severity = %s, want low (the KDC refuses both a TGT and a service ticket for a disabled computer account, measured against a real KDC - see docs/security-validation/results/computer-unconstrained-delegation-disabled-v2/VERDICT.md)", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "SVR02$" {
		t.Fatalf("AffectedEntities = %+v, want only SVR02$", findings[0].AffectedEntities)
	}
}

// TestUnconstrainedDelegationOnDisabledAccount_DescriptionDropsRefutedClaim
// guards the Description string returned by Detect(). Mutation M6: put the
// phrase "regardless of account status: a disabled computer account remains
// a valid delegation target" back into the Description literal and this
// test goes red.
func TestUnconstrainedDelegationOnDisabledAccount_DescriptionDropsRefutedClaim(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=SVR02,OU=Servers,DC=example,DC=com", SAMAccountName: "SVR02$", TrustedForDelegation: true, Disabled: true},
		},
	}
	findings := NewUnconstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
	if reComputerDelegationRefutedClaim.MatchString(findings[0].Description) {
		t.Fatalf("Description still asserts the refuted KDC claim: %q", findings[0].Description)
	}
	if reComputerDelegationClientErrorCode.MatchString(findings[0].Description) {
		t.Fatalf("Description carries a client-specific error code: %q", findings[0].Description)
	}
}

// TestUnconstrainedDelegationOnDisabledAccount_DocDropsRefutedClaim guards
// Doc().Description independently of Detect()'s Description: the catalog
// text is a separate copy (docs_gen.go), not test-coupled to the runtime
// string by the Go compiler. Mutation M7: put the refuted phrase back into
// docs_gen.go's Doc() literal for this detector and this test goes red.
func TestUnconstrainedDelegationOnDisabledAccount_DocDropsRefutedClaim(t *testing.T) {
	doc := NewUnconstrainedDelegationOnDisabledAccountDetector().Doc()
	if reComputerDelegationRefutedClaim.MatchString(doc.Description) {
		t.Fatalf("Doc().Description still asserts the refuted KDC claim: %q", doc.Description)
	}
	if reComputerDelegationClientErrorCode.MatchString(doc.Description) {
		t.Fatalf("Doc().Description carries a client-specific error code: %q", doc.Description)
	}
}

// TestUnconstrainedDelegationOnDisabledAccount_DescriptionAffirmsBothRefusals
// guards the POSITIVE claim: dropping the retired phrases is not enough if a
// paraphrase of the same falsehood takes their place. Mutation M8: replace
// the Description literal with a paraphrase that restates the refuted claim
// without using any retired phrase (e.g. "a coerced authentication against
// this account's SPN succeeds identically whether the account is active or
// disabled") and this test goes red, because "ticket-granting ticket" and
// "service ticket" both disappear along with the true claim.
func TestUnconstrainedDelegationOnDisabledAccount_DescriptionAffirmsBothRefusals(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=SVR02,OU=Servers,DC=example,DC=com", SAMAccountName: "SVR02$", TrustedForDelegation: true, Disabled: true},
		},
	}
	findings := NewUnconstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
	d := findings[0].Description
	if !reComputerDelegationTicketGrantingTicketWord.MatchString(d) || !reComputerDelegationServiceTicketWord.MatchString(d) {
		t.Fatalf("Description no longer positively states both KDC refusals (ticket-granting ticket, service ticket): %q", d)
	}
}

// TestUnconstrainedDelegationOnDisabledAccount_DocAffirmsBothRefusals is the
// Doc()-only counterpart: docs_gen.go is a separate copy, not test-coupled to
// Detect()'s Description by the Go compiler. Mutation M9: apply the same
// paraphrase to docs_gen.go's Doc() literal alone (Detect()'s Description
// stays correct) and this test goes red while
// TestUnconstrainedDelegationOnDisabledAccount_DescriptionAffirmsBothRefusals
// stays green - proving the two guards are independent.
func TestUnconstrainedDelegationOnDisabledAccount_DocAffirmsBothRefusals(t *testing.T) {
	doc := NewUnconstrainedDelegationOnDisabledAccountDetector().Doc()
	if !reComputerDelegationTicketGrantingTicketWord.MatchString(doc.Description) || !reComputerDelegationServiceTicketWord.MatchString(doc.Description) {
		t.Fatalf("Doc().Description no longer positively states both KDC refusals (ticket-granting ticket, service ticket): %q", doc.Description)
	}
}
