package kerberos

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// reUnconstrainedDelegationActiveTextGuard guards THIS ACTIVE (Critical)
// detector's text against reintroducing disabled accounts as covered: the
// bare word "disabled", and the specific formulas the KDC measurement in
// docs/security-validation/results/unconstrained-delegation-disabled-v2/VERDICT.md
// refuted (a disabled account is neither a valid delegation origin nor
// target, and the KDC does check the account's enabled state on both the TGT
// and the service-ticket path). Deliberately NOT shared with
// unconstrained-delegation-on-disabled-account_test.go's
// reUnconstrainedDelegationRefutedClaim: that detector's own Description
// legitimately talks about disabled accounts, so a bare "disabled" match
// would misfire there.
var reUnconstrainedDelegationActiveTextGuard = regexp.MustCompile(`(?i)\bdisabled\b|\bnever revalidates\b|\bnever checks\b|\bdoes not revalidate\b|\bregardless of account status\b|\bremains a valid delegation target\b|\bwhether enabled or disabled\b`)

// TestUnconstrainedDelegation covers the active-account half of the split.
// Measured live on the lab domain controller: 2 active accounts carried
// TRUSTED_FOR_DELEGATION (Administrator, n8n Service), 18 disabled accounts
// carried it too (17 with a real SPN), union = 20, intersection = 0 -
// cross-checked DN-by-DN against `public/dist/etc-collector audit ad`: 2/2
// and 18/18 identical, zero false positive, zero blind spot. See
// docs/security-validation/results/unconstrained-delegation-t245/VERDICT.md.
func TestUnconstrainedDelegation(t *testing.T) {
	userDN := "CN=svc,OU=Services,DC=test,DC=local"

	t.Run("active account with the bit fires here", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", UserAccountControl: types.UACTrustedForDelegation},
			},
			IncludeDetails: true,
		}
		findings := NewUnconstrainedDelegationDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 1 {
			t.Fatalf("active account with the bit must fire here, got %+v", findings)
		}
		if findings[0].Severity != types.SeverityCritical {
			t.Fatalf("active half must be Critical, got %s", findings[0].Severity)
		}
	})

	t.Run("disabled account does NOT fire here, even with the bit", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, UserAccountControl: types.UACTrustedForDelegation},
			},
		}
		findings := NewUnconstrainedDelegationDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("disabled account must be excluded from the active detector, got count=%d", findings[0].Count)
		}
	})

	t.Run("active account without the bit does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{{DN: userDN, SAMAccountName: "svc"}},
		}
		findings := NewUnconstrainedDelegationDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("an account without the bit must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("presence or absence of an SPN does not change whether the active half fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "with-spn", UserAccountControl: types.UACTrustedForDelegation, ServicePrincipalNames: []string{"CIFS/svc.test.local"}},
				{DN: userDN, SAMAccountName: "without-spn", UserAccountControl: types.UACTrustedForDelegation},
			},
		}
		findings := NewUnconstrainedDelegationDetector().Detect(context.Background(), data)
		if findings[0].Count != 2 {
			t.Fatalf("SPN presence must not affect the active detector's condition, got count=%d", findings[0].Count)
		}
	})
}

// TestUnconstrainedDelegation_PartitionIsExhaustive covers active and
// disabled accounts, ensuring the two detectors classify every account
// exactly once - no account counted twice, no account dropped. Verified on
// the code; the lab measurement referenced above shows the same
// invariant on real data: union (LDAP, state-independent) = 20 = 2 active +
// 18 disabled, measured separately.
func TestUnconstrainedDelegation_PartitionIsExhaustive(t *testing.T) {
	users := []types.User{
		{DN: "CN=active", SAMAccountName: "active", UserAccountControl: types.UACTrustedForDelegation},
		{DN: "CN=disabled", SAMAccountName: "disabled", Disabled: true, UserAccountControl: types.UACTrustedForDelegation},
		{DN: "CN=neither", SAMAccountName: "neither"},
	}
	data := &audit.DetectorData{Users: users, IncludeDetails: true}

	active := NewUnconstrainedDelegationDetector().Detect(context.Background(), data)
	disabled := NewUnconstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)

	if active[0].Count != 1 {
		t.Fatalf("active half: want 1, got %d", active[0].Count)
	}
	if disabled[0].Count != 1 {
		t.Fatalf("disabled half: want 1, got %d", disabled[0].Count)
	}
	if active[0].Count+disabled[0].Count != 2 {
		t.Fatalf("partition must total 2 affected accounts (3 users minus 1 with neither signal), got %d", active[0].Count+disabled[0].Count)
	}
}

// TestUnconstrainedDelegation_DescriptionNoDisabledLanguage guards the
// Description string returned by Detect(): this active/Critical detector's
// text must never claim to cover disabled accounts.
func TestUnconstrainedDelegation_DescriptionNoDisabledLanguage(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc,OU=Services,DC=test,DC=local", SAMAccountName: "svc", UserAccountControl: types.UACTrustedForDelegation},
		},
	}
	findings := NewUnconstrainedDelegationDetector().Detect(context.Background(), data)
	if reUnconstrainedDelegationActiveTextGuard.MatchString(findings[0].Description) {
		t.Fatalf("Description must not mention disabled accounts or a refuted KDC claim: %q", findings[0].Description)
	}
}

// TestUnconstrainedDelegation_DocNoDisabledLanguage is the Doc()-only
// counterpart: docs_gen.go is a separate copy, not test-coupled to Detect()'s
// Description by the Go compiler.
func TestUnconstrainedDelegation_DocNoDisabledLanguage(t *testing.T) {
	doc := NewUnconstrainedDelegationDetector().Doc()
	if reUnconstrainedDelegationActiveTextGuard.MatchString(doc.Description) {
		t.Fatalf("Doc().Description must not mention disabled accounts or a refuted KDC claim: %q", doc.Description)
	}
}

// TestUnconstrainedDelegation_DescriptionStartsWithEnabled guards the
// positive claim: the text must open by naming the population it actually
// covers.
func TestUnconstrainedDelegation_DescriptionStartsWithEnabled(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc,OU=Services,DC=test,DC=local", SAMAccountName: "svc", UserAccountControl: types.UACTrustedForDelegation},
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
