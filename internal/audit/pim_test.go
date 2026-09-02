package audit

import (
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestBuildPIMAssignmentsSummary_Counters(t *testing.T) {
	schedules := []types.RoleAssignment{
		{PrincipalID: "u1", PrincipalName: "Alice", UserPrincipalName: "alice@x", RoleID: "r-ga", RoleName: "Global Administrator", AssignmentType: "Assigned"},
		{PrincipalID: "u2", PrincipalName: "Bob", UserPrincipalName: "bob@x", RoleID: "r-ga", RoleName: "Global Administrator", AssignmentType: "Activated"},
		{PrincipalID: "u3", PrincipalName: "Carol", RoleID: "r-sa", RoleName: "Security Administrator", AssignmentType: "Assigned"},
		{PrincipalID: "u4", RoleID: "r-x", AssignmentType: "Eligible"}, // ignored — eligible doesn't go in active
	}
	eligibles := map[string]types.RoleAssignment{
		"k1": {PrincipalID: "u5", PrincipalName: "Dave", UserPrincipalName: "dave@x", RoleID: "r-ga", RoleName: "Global Administrator"},
		"k2": {PrincipalID: "u6", PrincipalName: "Eve", UserPrincipalName: "eve@x", RoleID: "r-sa", RoleName: "Security Administrator"},
	}
	// History: u5 self-activated GA → not in neverActivated. u6 has no selfActivate → in neverActivated.
	history := []types.PIMScheduleRequest{
		{Action: "selfActivate", PrincipalID: "u5", RoleID: "r-ga"},
		{Action: "adminAssign", PrincipalID: "u6", RoleID: "r-sa"}, // wrong action — does NOT count as activation
	}
	s := BuildPIMAssignmentsSummary(schedules, eligibles, history)

	if s.Active.Total != 3 {
		t.Errorf("Active.Total = %d, want 3", s.Active.Total)
	}
	if s.Active.ByAssignmentType["Assigned"] != 2 || s.Active.ByAssignmentType["Activated"] != 1 {
		t.Errorf("Active.ByAssignmentType = %v", s.Active.ByAssignmentType)
	}
	if len(s.Active.ByRole["Global Administrator"]) != 2 {
		t.Errorf("GA active entries = %d, want 2", len(s.Active.ByRole["Global Administrator"]))
	}
	if len(s.Active.ByRole["Security Administrator"]) != 1 {
		t.Errorf("SA active entries = %d, want 1", len(s.Active.ByRole["Security Administrator"]))
	}
	if s.Eligible.Total != 2 {
		t.Errorf("Eligible.Total = %d, want 2", s.Eligible.Total)
	}
	if len(s.NeverActivated) != 1 {
		t.Fatalf("NeverActivated = %d, want 1 (Eve never selfActivated)", len(s.NeverActivated))
	}
	if s.NeverActivated[0].PrincipalID != "u6" {
		t.Errorf("NeverActivated[0] = %s, want u6", s.NeverActivated[0].PrincipalID)
	}
	if s.NeverActivated[0].LastActivation != nil {
		t.Errorf("NeverActivated[0].LastActivation must be null per spec, got %v", s.NeverActivated[0].LastActivation)
	}
}

func TestBuildPIMAssignmentsSummary_LegacyLowercaseAssignmentType(t *testing.T) {
	// GetRoleAssignments emits "direct" (lowercase). Make sure it maps to
	// "Assigned" so the Schedules-fed downstream consumers see one canonical
	// value.
	schedules := []types.RoleAssignment{
		{PrincipalID: "u1", RoleID: "r-ga", RoleName: "Global Administrator", AssignmentType: "direct"},
		{PrincipalID: "u2", RoleID: "r-ga", RoleName: "Global Administrator", AssignmentType: "activated"},
	}
	s := BuildPIMAssignmentsSummary(schedules, nil, nil)
	if s.Active.ByAssignmentType["Assigned"] != 1 {
		t.Errorf("legacy 'direct' should map to Assigned: %v", s.Active.ByAssignmentType)
	}
	if s.Active.ByAssignmentType["Activated"] != 1 {
		t.Errorf("legacy 'activated' should map to Activated: %v", s.Active.ByAssignmentType)
	}
}

func TestBuildPIMAssignmentsSummary_EmptyInputs(t *testing.T) {
	s := BuildPIMAssignmentsSummary(nil, nil, nil)
	if s == nil {
		t.Fatal("nil result")
	}
	if s.Active.Total != 0 || s.Eligible.Total != 0 || len(s.NeverActivated) != 0 {
		t.Errorf("empty inputs should produce zero-valued summary")
	}
	// Maps must be initialised so JSON renders {} not null.
	if s.Active.ByAssignmentType == nil || s.Active.ByRole == nil || s.Eligible.ByRole == nil {
		t.Errorf("maps must be non-nil for stable JSON shape")
	}
}

func TestBuildPIMAssignmentsSummary_NeverActivatedSortedStable(t *testing.T) {
	eligibles := map[string]types.RoleAssignment{
		"k1": {PrincipalID: "u-zoe", UserPrincipalName: "zoe@x", PrincipalName: "Zoe", RoleID: "r1", RoleName: "Role A"},
		"k2": {PrincipalID: "u-alice", UserPrincipalName: "alice@x", PrincipalName: "Alice", RoleID: "r1", RoleName: "Role A"},
		"k3": {PrincipalID: "u-bob", UserPrincipalName: "bob@x", PrincipalName: "Bob", RoleID: "r2", RoleName: "Role B"},
	}
	s := BuildPIMAssignmentsSummary(nil, eligibles, nil)
	if len(s.NeverActivated) != 3 {
		t.Fatalf("NeverActivated len=%d, want 3", len(s.NeverActivated))
	}
	// Expected order: Role A/alice, Role A/zoe, Role B/bob (sort by role then UPN).
	wantOrder := []string{"alice@x", "zoe@x", "bob@x"}
	for i, e := range s.NeverActivated {
		if e.PrincipalUpn != wantOrder[i] {
			t.Errorf("NeverActivated[%d] = %s, want %s", i, e.PrincipalUpn, wantOrder[i])
		}
	}
}

func TestBuildPIMActivationHistorySummary_ByActionCounters(t *testing.T) {
	requests := []types.PIMScheduleRequest{
		{Action: "selfActivate"},
		{Action: "selfActivate"},
		{Action: "adminAssign"},
		{Action: "adminRemove"},
		{Action: ""}, // empty action — not counted
	}
	h := BuildPIMActivationHistorySummary(requests)
	if h.TotalRequests != 5 {
		t.Errorf("TotalRequests = %d, want 5", h.TotalRequests)
	}
	if h.ByAction["selfActivate"] != 2 || h.ByAction["adminAssign"] != 1 || h.ByAction["adminRemove"] != 1 {
		t.Errorf("ByAction = %v", h.ByAction)
	}
	if _, hasEmpty := h.ByAction[""]; hasEmpty {
		t.Errorf("empty action should not create a bucket")
	}
	if len(h.Events) != 5 {
		t.Errorf("Events should pass through unchanged: len=%d", len(h.Events))
	}
}

func TestBuildPIMActivationHistorySummary_Empty(t *testing.T) {
	h := BuildPIMActivationHistorySummary(nil)
	if h == nil || h.TotalRequests != 0 {
		t.Errorf("empty input should produce zero summary")
	}
}

func TestBuildEntry_TimestampPropagation(t *testing.T) {
	now := time.Now().UTC()
	ra := &types.RoleAssignment{
		PrincipalID:      "u1",
		StartDateTime:    now,
		CreatedDateTime:  now.Add(-365 * 24 * time.Hour),
		DirectoryScopeID: "/",
	}
	e := buildEntry(ra, "Assigned")
	if e.StartDateTime == nil || !e.StartDateTime.Equal(now) {
		t.Errorf("StartDateTime not propagated")
	}
	if e.CreatedDateTime == nil || !e.CreatedDateTime.Equal(now.Add(-365*24*time.Hour)) {
		t.Errorf("CreatedDateTime not propagated")
	}
	if e.EndDateTime != nil {
		t.Errorf("zero EndDateTime should propagate as nil, got %v", e.EndDateTime)
	}
}
