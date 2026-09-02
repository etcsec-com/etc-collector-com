package anssi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestComputersToEntities_PopulatesRealFields covers T_127: a prior
// hand-built AffectedEntity here only set Type/DN/SAMAccountName, leaving
// Enabled/PasswordLastSet/LastLogon/MemberOf at their Go zero values
// (false/nil/nil/nil) — indistinguishable in the published JSON from a real
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
		t.Error("Enabled = false, want true — an active DC must not be published as disabled")
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
	if got.OperatingSystem != comp.OperatingSystem {
		t.Errorf("OperatingSystem = %q, want %q", got.OperatingSystem, comp.OperatingSystem)
	}

	// includeDetails=false must still suppress entities entirely.
	if ents := computersToEntities([]types.Computer{comp}, false); ents != nil {
		t.Errorf("includeDetails=false: expected nil entities, got %v", ents)
	}
}

// TestR40NoPSOTier0_EntityOrderIsDeterministic covers T_046/B_048: the
// uncovered Tier 0 groups come from helpers.Tier0Groups, a map, so ranging it
// directly to build entities would give a randomized order per process. With
// several Tier 0 groups and no PSO covering any of them, an unsorted range
// would very rarely land in DN order by chance across repeated calls —
// asserting the exact expected order pins the sort.
func TestR40NoPSOTier0_EntityOrderIsDeterministic(t *testing.T) {
	const domainDN = "DC=example,DC=com"
	groups := []types.Group{
		{DN: "CN=Domain Admins,CN=Users," + domainDN, SAMAccountName: "Domain Admins"},
		{DN: "CN=Enterprise Admins,CN=Users," + domainDN, SAMAccountName: "Enterprise Admins"},
		{DN: "CN=Schema Admins,CN=Users," + domainDN, SAMAccountName: "Schema Admins"},
		{DN: "CN=Administrators,CN=Builtin," + domainDN, SAMAccountName: "Administrators"},
	}

	// helpers.Tier0Groups keys its set by LOWERCASE DN, and data.EntityForDN
	// does an exact (case-sensitive) map lookup against data.ObjectByDN — so
	// with no ObjectByDN cache populated (as here), the entities come back
	// unresolved with the lowercase DN. That case-sensitivity gap is
	// pre-existing and not what this test is about; it just means the
	// expected DNs below are lowercase to match real behavior.
	lowerDomainDN := strings.ToLower(domainDN)
	want := []string{
		"cn=administrators,cn=builtin," + lowerDomainDN,
		"cn=domain admins,cn=users," + lowerDomainDN,
		"cn=enterprise admins,cn=users," + lowerDomainDN,
		"cn=schema admins,cn=users," + lowerDomainDN,
	}

	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: domainDN},
		Groups:         groups,
		// No FGPPs at all — none of the Tier 0 groups is covered by a PSO.
	}

	for i := 0; i < 5; i++ {
		findings := NewR40NoPSOTier0Detector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("run %d: expected exactly 1 finding, got %d", i, len(findings))
		}
		ents := findings[0].AffectedEntities
		if len(ents) != len(want) {
			t.Fatalf("run %d: expected %d entities, got %d (%v)", i, len(want), len(ents), ents)
		}
		for j, ent := range ents {
			if ent.DN != want[j] {
				t.Fatalf("run %d: entity order not deterministic — position %d = %q, want %q", i, j, ent.DN, want[j])
			}
		}
	}
}
