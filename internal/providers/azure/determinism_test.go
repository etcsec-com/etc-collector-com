package azure

import (
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// T_049 (routed from ad's T_046/B_048 sweep): two more map-range-into-output
// sites, found while reviewing every map declaration in this package for the
// same bug the ticket named in the mfa-suspicious-activity detector.
//
// Both mergeRoleAssignments and sortedSetKeys were extracted out of live
// Graph-calling methods (GetRoleAssignments, enrichAppRegistrations)
// specifically so their ordering is unit-testable without a live tenant — the
// frozen bench (T_044) only replays an LDAP thread and cannot exercise this
// path at all, per the ticket's own "Vérification" note.
//
// Both tests use 6+ distinct keys so an accidental sorted match on a single
// run is implausible (1/720), and both loop 5 times: without the sort, at
// least one of the 5 runs almost certainly lands out of order.

// TestMergeRoleAssignments_OrderIsDeterministic is the higher-impact site of
// the two: AzureRoleAssignments feeds ~14 detector files (PIM, all of
// privileged-access/roles, membership/unresolved-members, and the geo-admin
// detector from T_001), none of which re-sort it — they all trust the
// provider's order. A single fix here makes every one of them deterministic
// at once, the same way engine.go's fix in T_046 covered the AD side broadly.
func TestMergeRoleAssignments_OrderIsDeterministic(t *testing.T) {
	activeMap := map[string]types.RoleAssignment{
		"a|r1|": {ID: "zulu-id", PrincipalID: "a", RoleID: "r1"},
		"b|r1|": {ID: "yankee-id", PrincipalID: "b", RoleID: "r1"},
		"c|r1|": {ID: "xray-id", PrincipalID: "c", RoleID: "r1"},
	}
	eligibilityMap := map[string]types.RoleAssignment{
		"d|r2|": {ID: "whiskey-id", PrincipalID: "d", RoleID: "r2"},
		"e|r2|": {ID: "victor-id", PrincipalID: "e", RoleID: "r2"},
		"f|r2|": {ID: "uniform-id", PrincipalID: "f", RoleID: "r2"},
	}
	policyMap := map[string]types.RolePIMPolicy{}

	want := []string{"uniform-id", "victor-id", "whiskey-id", "xray-id", "yankee-id", "zulu-id"}

	for i := 0; i < 5; i++ {
		got := mergeRoleAssignments(activeMap, eligibilityMap, policyMap)
		if len(got) != len(want) {
			t.Fatalf("run %d: expected %d assignments, got %d", i, len(want), len(got))
		}
		for j, a := range got {
			if a.ID != want[j] {
				t.Fatalf("run %d: order not deterministic — position %d = %q, want %q", i, j, a.ID, want[j])
			}
		}
	}
}

// TestMergeRoleAssignments_PolicyEnrichmentSurvivesSort confirms the sort is
// purely a reordering step: eligible-only entries still get their PIM policy
// fields filled in regardless of where they land after sort.Slice.
func TestMergeRoleAssignments_PolicyEnrichmentSurvivesSort(t *testing.T) {
	requiresApproval := true
	activeMap := map[string]types.RoleAssignment{}
	eligibilityMap := map[string]types.RoleAssignment{
		"a|r1|": {ID: "assignment-1", PrincipalID: "a", RoleID: "r1"},
	}
	policyMap := map[string]types.RolePIMPolicy{
		"r1|": {RequiresApproval: &requiresApproval, MaximumDuration: "PT8H"},
	}

	got := mergeRoleAssignments(activeMap, eligibilityMap, policyMap)
	if len(got) != 1 {
		t.Fatalf("expected 1 assignment, got %d", len(got))
	}
	if !got[0].RequiresApproval {
		t.Error("RequiresApproval was not carried over from the policy")
	}
	if got[0].ActivationDuration != "PT8H" {
		t.Errorf("ActivationDuration = %q, want PT8H", got[0].ActivationDuration)
	}
}

// TestSortedSetKeys_OrderIsDeterministic covers enrichAppRegistrations'
// AppRegistration.ApiPermissions: permSet dedupes permission names collected
// from RequiredResourceAccess and OAuth2 grants, and was ranged directly into
// the field before this fix.
func TestSortedSetKeys_OrderIsDeterministic(t *testing.T) {
	set := map[string]bool{
		"Zulu.Read.All": true, "Yankee.Read.All": true, "Xray.Read.All": true,
		"Whiskey.Read.All": true, "Victor.Read.All": true, "Uniform.Read.All": true,
	}
	want := []string{
		"Uniform.Read.All", "Victor.Read.All", "Whiskey.Read.All",
		"Xray.Read.All", "Yankee.Read.All", "Zulu.Read.All",
	}

	for i := 0; i < 5; i++ {
		got := sortedSetKeys(set)
		if len(got) != len(want) {
			t.Fatalf("run %d: expected %d keys, got %d", i, len(want), len(got))
		}
		for j, k := range got {
			if k != want[j] {
				t.Fatalf("run %d: order not deterministic — position %d = %q, want %q", i, j, k, want[j])
			}
		}
	}
}

func TestSortedSetKeys_Empty(t *testing.T) {
	if got := sortedSetKeys(map[string]bool{}); len(got) != 0 {
		t.Errorf("expected empty slice, got %v", got)
	}
	if got := sortedSetKeys(nil); len(got) != 0 {
		t.Errorf("expected empty slice for nil map, got %v", got)
	}
}
