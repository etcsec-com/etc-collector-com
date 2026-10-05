package anssi

import (
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestUsersToEntities_PopulatesEnabled: usersToEntities built
// AffectedEntity literals without setting Enabled, so every entity defaulted
// to Go's zero value (false). response.go's annotateDisabledAccounts reads
// that same field to report how many affected accounts can't authenticate -
// with the field never set, a fully active/enabled user was published and
// scored as if it were disabled, for every detector routing through this
// helper (anssi-r6-inactive-accounts.go, anssi-r7-stale-accounts-not-
// removed.go, anssi-r8-service-accounts-as-users.go, anssi-r9-service-
// account-secret-rotation.go).
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

// TestComputersToEntities_PopulatesRealFields covers a bug where a prior
// hand-built AffectedEntity here only set Type/DN/SAMAccountName, leaving
// Enabled/PasswordLastSet/LastLogon/MemberOf at their Go zero values
// (false/nil/nil/nil) - indistinguishable in the published JSON from a real
// disabled, never-logged-on, group-less computer account. R19
// (ANSSI_R19_SERVER_CORE_NOT_USED) and R43 (ANSSI_R43_DC_PASSWORD_OLD) both
// call this helper; a zeroed Enabled also fed response.go's
// annotateDisabledAccounts and silently zeroed their compliance-score
// contribution for an active DC.
func TestComputersToEntities_PopulatesRealFields(t *testing.T) {
	pwdLastSet := time.Date(2026, 8, 10, 13, 39, 22, 0, time.UTC)
	lastLogon := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	comp := types.Computer{
		DN:              "CN=DC-01,OU=Domain Controllers,DC=lab,DC=local",
		SAMAccountName:  "DC-01$",
		OperatingSystem: "Windows Server 2022 Datacenter Evaluation",
		Disabled:        false, // active machine account
		MemberOf:        []string{"CN=Domain Controllers,CN=Users,DC=lab,DC=local"},
		PasswordLastSet: pwdLastSet,
		LastLogon:       lastLogon,
	}

	ents := computersToEntities([]types.Computer{comp}, true)
	if len(ents) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(ents))
	}
	got := ents[0]

	if !got.Enabled {
		t.Error("Enabled = false, want true - an active DC must not be published as disabled")
	}
	if got.PasswordLastSet == nil || *got.PasswordLastSet == "" {
		t.Error("PasswordLastSet not populated, want the real pwdLastSet timestamp")
	}
	if got.LastLogon == nil || *got.LastLogon == "" {
		t.Error("LastLogon not populated, want the real lastLogon timestamp")
	}
	if len(got.MemberOf) != 1 || got.MemberOf[0] != comp.MemberOf[0] {
		t.Errorf("MemberOf = %v, want %v", got.MemberOf, comp.MemberOf)
	}
}

// TestIsWellKnownAdminTrustee covers acceptance §3: the "s-1-5-21-" substring
// excluded every domain principal - the exact population these checks target.
func TestIsWellKnownAdminTrustee(t *testing.T) {
	cases := []struct {
		trustee string
		want    bool
		why     string
	}{
		{sidHelpdesk, false, "ordinary domain group must NOT be treated as a built-in admin"},
		{"S-1-5-21-1234567890-1111111111-2222222222-1105", false, "ordinary domain user"},
		{sidDomainAdmins, true, "Domain Admins (-512)"},
		{"S-1-5-21-1234567890-1111111111-2222222222-519", true, "Enterprise Admins (-519)"},
		{"S-1-5-32-544", true, "BUILTIN\\Administrators"},
		{"S-1-5-18", true, "LOCAL SYSTEM"},
		{"S-1-5-10", true, "SELF"},
		{"S-1-3-0", true, "CREATOR OWNER"},
		{sidPreWin2000, false, "Pre-Windows 2000 Compatible Access is NOT an admin principal"},
		{"S-1-1-0", false, "Everyone"},
		{"DOMAIN\\Domain Admins", true, "friendly-name fallback still works"},
	}
	for _, tc := range cases {
		if got := isWellKnownAdminTrustee(tc.trustee); got != tc.want {
			t.Errorf("isWellKnownAdminTrustee(%q) = %v, want %v - %s", tc.trustee, got, tc.want, tc.why)
		}
	}
}
