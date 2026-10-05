package kerberos

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestConstrainedDelegation covers the fact that CONSTRAINED_DELEGATION only
// tested the UAC bit TRUSTED_TO_AUTH_FOR_DELEGATION (protocol transition,
// S4U2Self+S4U2Proxy) and never read msDS-AllowedToDelegateTo - so classic
// Kerberos-only constrained delegation (S4U2Proxy alone, no UAC bit) was
// completely invisible. Planted live on DC01 via the existing
// docs/security-validation/fixtures/delegation/G2a-constrained-kcdonly.ps1
// fixture (unmodified): before=17/after=18/revert=17 on the real domain,
// confirming this predicate - not just the fixture's synthetic shape below.
func TestConstrainedDelegation(t *testing.T) {
	userDN := "CN=svc,OU=Services,DC=test,DC=local"

	t.Run("Kerberos-only (no protocol transition) DOES fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", AllowedToDelegateTo: []string{"HOST/dc-01.test.local"}},
			},
			IncludeDetails: true,
		}
		findings := NewConstrainedDelegationDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 1 {
			t.Fatalf("Kerberos-only constrained delegation must fire, got %+v", findings)
		}
	})

	t.Run("protocol transition (UAC bit) still fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", UserAccountControl: types.UACTrustedToAuthForDelegation},
			},
			IncludeDetails: true,
		}
		findings := NewConstrainedDelegationDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 1 {
			t.Fatalf("protocol-transition constrained delegation must still fire, got %+v", findings)
		}
	})

	t.Run("both set counts once, not twice", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", UserAccountControl: types.UACTrustedToAuthForDelegation, AllowedToDelegateTo: []string{"HOST/dc-01.test.local"}},
			},
		}
		findings := NewConstrainedDelegationDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("one account with both signals must count once, got count=%d", findings[0].Count)
		}
	})

	t.Run("neither set does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{{DN: userDN, SAMAccountName: "svc"}},
		}
		findings := NewConstrainedDelegationDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("an account with neither signal must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled account, Kerberos-only branch, does NOT fire here", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, AllowedToDelegateTo: []string{"HOST/dc-01.test.local"}},
			},
		}
		findings := NewConstrainedDelegationDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("disabled account (attribute branch) must be excluded from the active detector, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled account, protocol transition branch, does NOT fire here", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, UserAccountControl: types.UACTrustedToAuthForDelegation},
			},
		}
		findings := NewConstrainedDelegationDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("disabled account (bit branch) must be excluded from the active detector, got count=%d", findings[0].Count)
		}
	})
}

// TestConstrainedDelegation_PartitionIsExhaustive covers both branches, active
// and disabled, ensuring the two detectors classify every account exactly
// once - no account counted twice, no account dropped.
func TestConstrainedDelegation_PartitionIsExhaustive(t *testing.T) {
	users := []types.User{
		{DN: "CN=active-bit", SAMAccountName: "active-bit", UserAccountControl: types.UACTrustedToAuthForDelegation},
		{DN: "CN=active-attr", SAMAccountName: "active-attr", AllowedToDelegateTo: []string{"HOST/x"}},
		{DN: "CN=disabled-bit", SAMAccountName: "disabled-bit", Disabled: true, UserAccountControl: types.UACTrustedToAuthForDelegation},
		{DN: "CN=disabled-attr", SAMAccountName: "disabled-attr", Disabled: true, AllowedToDelegateTo: []string{"HOST/x"}},
		{DN: "CN=neither", SAMAccountName: "neither"},
	}
	data := &audit.DetectorData{Users: users, IncludeDetails: true}

	active := NewConstrainedDelegationDetector().Detect(context.Background(), data)
	disabled := NewConstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)

	if active[0].Count != 2 {
		t.Fatalf("active half: want 2 (active-bit, active-attr), got %d", active[0].Count)
	}
	if disabled[0].Count != 2 {
		t.Fatalf("disabled half: want 2 (disabled-bit, disabled-attr), got %d", disabled[0].Count)
	}
	if active[0].Count+disabled[0].Count != 4 {
		t.Fatalf("partition must total 4 affected accounts (5 users minus 1 with neither signal), got %d", active[0].Count+disabled[0].Count)
	}
}
