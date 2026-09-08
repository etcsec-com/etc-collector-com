package anssi

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestUsersToEntities_PopulatesEnabled: usersToEntities built
// AffectedEntity literals without setting Enabled, so every entity defaulted
// to Go's zero value (false). response.go's annotateDisabledAccounts reads
// that same field to report how many affected accounts can't authenticate -
// with the field never set, a fully active/enabled user was published and
// scored as if it were disabled, for every detector in this file (R6/R7/R8/R9
// all route through this helper).
func TestUsersToEntities_PopulatesEnabled(t *testing.T) {
	active := types.User{DN: "CN=Active,DC=lab,DC=local", SAMAccountName: "active", Disabled: false}
	disabled := types.User{DN: "CN=Disabled,DC=lab,DC=local", SAMAccountName: "disabled", Disabled: true}

	entities := usersToEntities([]types.User{active, disabled}, true)
	if len(entities) != 2 {
		t.Fatalf("expected 2 entities, got %d", len(entities))
	}
	if !entities[0].Enabled {
		t.Errorf("active user: Enabled = false, want true (DN=%s)", entities[0].DN)
	}
	if entities[1].Enabled {
		t.Errorf("disabled user: Enabled = true, want false (DN=%s)", entities[1].DN)
	}
}

// TestR6InactiveAccounts_ActiveUserNotReportedAsDisabled reproduces the bug
// end-to-end through the detector: before the fix, an active (non-disabled)
// user inactive for 91 days came back from the detector with
// AffectedEntities[0].Enabled == false, indistinguishable from a genuinely
// disabled account.
func TestR6InactiveAccounts_ActiveUserNotReportedAsDisabled(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	staleLogon := now.AddDate(0, 0, -91)
	data := &audit.DetectorData{
		Now:            now,
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=Active,DC=lab,DC=local", SAMAccountName: "active", Disabled: false, LastLogonTimestamp: staleLogon},
		},
	}
	findings := NewR6InactiveAccountsDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 || len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("expected 1 finding with 1 affected entity, got %+v", findings)
	}
	if !findings[0].AffectedEntities[0].Enabled {
		t.Errorf("active-but-inactive user reported as Enabled=false; it must be published as enabled since it can still authenticate")
	}
}

// TestR7StaleAccounts_NeverLoggedOnFallsBackToCreated: a
// disabled account that never logged on has LastLogon/LastLogonTimestamp
// both zero. The detector used to require `!last.IsZero()` before comparing
// to the threshold, so a never-used disabled account - the worst case for
// this check, not a safe one - was silently skipped forever. This test would
// have FAILED against the old implementation (no finding) and passes now
// that a zero last-logon falls back to Created (whenCreated).
func TestR7StaleAccounts_NeverLoggedOnFallsBackToCreated(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:             "CN=Never Used,DC=lab,DC=local",
				SAMAccountName: "neverused",
				Disabled:       true,
				Created:        now.AddDate(0, 0, -200), // created 200 days ago, never logged on
			},
		},
	}
	findings := NewR7StaleAccountsNotRemovedDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a disabled, never-logged-on account created 200 days ago to be flagged, got %+v", findings)
	}
}

// TestR9ServiceAccountRotation_NeverSetPasswordIsFlagged: a
// service account with pwdLastSet=0 (password never actually set through
// normal rotation) is the worst case for secret staleness, not a safe one.
// The detector used to require `!u.PasswordLastSet.IsZero()` before
// comparing to the threshold, silently excluding exactly these accounts.
// This test would have FAILED against the old implementation (no finding)
// and passes now that a zero PasswordLastSet is treated as maximally stale.
func TestR9ServiceAccountRotation_NeverSetPasswordIsFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:                    "CN=svc-legacy,DC=lab,DC=local",
				SAMAccountName:        "svc-legacy",
				Disabled:              false,
				PasswordNeverExpires:  true,
				ServicePrincipalNames: []string{"HTTP/legacy.lab.local"},
				// PasswordLastSet intentionally left zero.
			},
		},
	}
	findings := NewR9ServiceAccountSecretRotationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a service account with pwdLastSet=0 to be flagged as never-rotated, got %+v", findings)
	}
}

// TestR14RBCDAudit_ScopedToDomainControllers: ANSSI PA-099 R65
// (p.90-91) flags RBCD specifically when its target is a Tier 0 resource.
// The previous implementation counted RBCD on ANY computer, including
// ordinary Tier 2 member servers where RBCD is a normal, sanctioned
// delegation pattern (e.g. an app server delegating to a print spooler) -
// wildly over-broad relative to what R65 actually prohibits. This test
// would have FAILED against the old implementation (both computers counted)
// and passes now that only RBCD on a domain controller is flagged.
func TestR14RBCDAudit_ScopedToDomainControllers(t *testing.T) {
	dc := types.Computer{DN: "CN=DC01,OU=Domain Controllers,DC=lab,DC=local", SAMAccountName: "DC01$", AllowedToActOnBehalfOfOtherIdentity: []byte{0x01}}
	memberServer := types.Computer{DN: "CN=APP01,OU=Servers,DC=lab,DC=local", SAMAccountName: "APP01$", AllowedToActOnBehalfOfOtherIdentity: []byte{0x01}}
	data := &audit.DetectorData{
		IncludeDetails:    true,
		DomainControllers: []types.Computer{dc},
		Computers:         []types.Computer{dc, memberServer},
	}
	findings := NewR14RBCDAuditDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected only the domain controller's RBCD to be flagged, got %+v", findings)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].DN != dc.DN {
		t.Fatalf("expected the flagged entity to be the DC, got %+v", findings[0].AffectedEntities)
	}
}
