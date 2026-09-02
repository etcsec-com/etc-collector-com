package audit

import (
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestIsAIAgentRole(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"Agent ID Administrator", true},
		{"Agent ID Developer", true},
		{"Agent Registry Administrator", true},
		{"AI Administrator", true},
		{"AI Reader", true},
		{"Copilot Studio Administrator", true},
		{"Microsoft Copilot Builder", true},
		{"Knowledge Administrator", true},
		{"Knowledge Curator", true},
		{"Global Administrator", false},
		{"User Administrator", false},
		{"Aircraft Administrator", false}, // "Air"-prefix shouldn't match the "AI " filter
		{"", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isAIAgentRole(c.name); got != c.want {
				t.Errorf("isAIAgentRole(%q) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

func TestBuildAIAgentRolesSummary_NoMatchingRoles(t *testing.T) {
	d := &DetectorData{
		AzureDirectoryRoles: []types.DirectoryRole{
			{ID: "ga-id", DisplayName: "Global Administrator"},
			{ID: "ua-id", DisplayName: "User Administrator"},
		},
	}
	got := BuildAIAgentRolesSummary(d, nil, "test")
	if got == nil {
		t.Fatal("nil summary")
	}
	if !got.Available {
		t.Error("Available should be true even when no AI roles match")
	}
	if len(got.RolesMonitored) != 0 {
		t.Errorf("RolesMonitored = %v, want []", got.RolesMonitored)
	}
	if got.TotalAssignments != 0 {
		t.Errorf("TotalAssignments = %d, want 0", got.TotalAssignments)
	}
	if len(got.Assignments) != 0 {
		t.Errorf("Assignments len = %d, want 0", len(got.Assignments))
	}
}

func TestBuildAIAgentRolesSummary_DirectUserActive(t *testing.T) {
	d := &DetectorData{
		AzureDirectoryRoles: []types.DirectoryRole{
			{ID: "agent-id-admin", DisplayName: "Agent ID Administrator"},
		},
		AzureRoleAssignments: []types.RoleAssignment{
			{
				ID:                "ra-1",
				PrincipalID:       "user-1",
				PrincipalType:     "User",
				PrincipalName:     "John Admin",
				UserPrincipalName: "john@tenant.onmicrosoft.com",
				RoleID:            "agent-id-admin",
				IsEligible:        false,
				CreatedDateTime:   time.Date(2026, 2, 14, 10, 23, 0, 0, time.UTC),
			},
		},
	}
	got := BuildAIAgentRolesSummary(d, nil, "test")
	if got == nil {
		t.Fatal("nil")
	}
	if got.TotalAssignments != 1 {
		t.Errorf("TotalAssignments = %d, want 1", got.TotalAssignments)
	}
	if got.ActiveAssignments != 1 {
		t.Errorf("ActiveAssignments = %d, want 1", got.ActiveAssignments)
	}
	if got.EligibleAssignments != 0 {
		t.Errorf("EligibleAssignments = %d, want 0", got.EligibleAssignments)
	}
	if got.ExpandedHumanCount != 1 {
		t.Errorf("ExpandedHumanCount = %d, want 1", got.ExpandedHumanCount)
	}
	a := got.Assignments[0]
	if a.AssignmentType != "active" {
		t.Errorf("AssignmentType = %q, want active", a.AssignmentType)
	}
	if a.AssignmentSource != "direct" {
		t.Errorf("AssignmentSource = %q, want direct", a.AssignmentSource)
	}
	if a.Principal.UserPrincipalName != "john@tenant.onmicrosoft.com" {
		t.Errorf("UPN = %q, want john@tenant.onmicrosoft.com", a.Principal.UserPrincipalName)
	}
	if got.RolesMonitored[0] != "Agent ID Administrator" {
		t.Errorf("RolesMonitored[0] = %q", got.RolesMonitored[0])
	}
}

func TestBuildAIAgentRolesSummary_GroupExpansion(t *testing.T) {
	d := &DetectorData{
		AzureDirectoryRoles: []types.DirectoryRole{
			{ID: "agent-id-admin", DisplayName: "Agent ID Administrator"},
		},
		AzureRoleAssignments: []types.RoleAssignment{
			{
				ID:            "ra-1",
				PrincipalID:   "group-1",
				PrincipalType: "Group",
				PrincipalName: "All Cloud Admins",
				RoleID:        "agent-id-admin",
				IsEligible:    false,
			},
		},
	}
	groupMembers := map[string][]types.GroupMember{
		"group-1": {
			{ID: "u1", Type: "user", DisplayName: "Alice", UserPrincipalName: "alice@t.com"},
			{ID: "u2", Type: "user", DisplayName: "Bob", UserPrincipalName: "bob@t.com"},
			{ID: "u3", Type: "user", DisplayName: "Carol", UserPrincipalName: "carol@t.com"},
		},
	}
	got := BuildAIAgentRolesSummary(d, groupMembers, "test")
	if got.TotalAssignments != 1 {
		t.Errorf("TotalAssignments = %d, want 1", got.TotalAssignments)
	}
	if got.GroupAssignmentsCount != 1 {
		t.Errorf("GroupAssignmentsCount = %d, want 1", got.GroupAssignmentsCount)
	}
	if got.ExpandedHumanCount != 3 {
		t.Errorf("ExpandedHumanCount = %d, want 3 (3 group members)", got.ExpandedHumanCount)
	}
	a := got.Assignments[0]
	if a.AssignmentSource != "group" {
		t.Errorf("AssignmentSource = %q, want group", a.AssignmentSource)
	}
	if a.ExpandedMembersCount != 3 {
		t.Errorf("ExpandedMembersCount = %d, want 3", a.ExpandedMembersCount)
	}
	if len(a.ExpandedMembers) != 3 {
		t.Errorf("ExpandedMembers len = %d, want 3", len(a.ExpandedMembers))
	}
}

func TestBuildAIAgentRolesSummary_DedupHumansAcrossDirectAndGroup(t *testing.T) {
	d := &DetectorData{
		AzureDirectoryRoles: []types.DirectoryRole{
			{ID: "agent-id-admin", DisplayName: "Agent ID Administrator"},
		},
		AzureRoleAssignments: []types.RoleAssignment{
			{
				ID:                "ra-1",
				PrincipalID:       "u-alice",
				PrincipalType:     "User",
				UserPrincipalName: "alice@t.com",
				RoleID:            "agent-id-admin",
			},
			{
				ID:            "ra-2",
				PrincipalID:   "group-1",
				PrincipalType: "Group",
				PrincipalName: "Cloud Admins",
				RoleID:        "agent-id-admin",
			},
		},
	}
	groupMembers := map[string][]types.GroupMember{
		// Alice is also in the group → must NOT be double-counted
		"group-1": {
			{ID: "u-alice", Type: "user", UserPrincipalName: "alice@t.com"},
			{ID: "u-bob", Type: "user", UserPrincipalName: "bob@t.com"},
			{ID: "u-carol", Type: "user", UserPrincipalName: "carol@t.com"},
		},
	}
	got := BuildAIAgentRolesSummary(d, groupMembers, "test")
	if got.ExpandedHumanCount != 3 {
		t.Errorf("ExpandedHumanCount = %d, want 3 (alice deduped)", got.ExpandedHumanCount)
	}
}

func TestBuildAIAgentRolesSummary_EligiblePIM(t *testing.T) {
	d := &DetectorData{
		AzureDirectoryRoles: []types.DirectoryRole{
			{ID: "agent-id-admin", DisplayName: "Agent ID Administrator"},
		},
		AzureRoleAssignments: []types.RoleAssignment{
			{
				ID:             "ra-1",
				PrincipalID:    "user-1",
				PrincipalType:  "User",
				RoleID:         "agent-id-admin",
				IsEligible:     true,
				AssignmentType: "activated",
			},
		},
	}
	got := BuildAIAgentRolesSummary(d, nil, "test")
	if got.EligibleAssignments != 1 {
		t.Errorf("EligibleAssignments = %d, want 1", got.EligibleAssignments)
	}
	if got.ActiveAssignments != 0 {
		t.Errorf("ActiveAssignments = %d, want 0", got.ActiveAssignments)
	}
	if got.Assignments[0].AssignmentSource != "pim" {
		t.Errorf("AssignmentSource = %q, want pim", got.Assignments[0].AssignmentSource)
	}
	if got.Assignments[0].AssignmentType != "eligible" {
		t.Errorf("AssignmentType = %q, want eligible", got.Assignments[0].AssignmentType)
	}
}

func TestBuildAIAgentRolesSummary_ServicePrincipalResolvesAppID(t *testing.T) {
	d := &DetectorData{
		AzureDirectoryRoles: []types.DirectoryRole{
			{ID: "ai-admin", DisplayName: "AI Administrator"},
		},
		AzureRoleAssignments: []types.RoleAssignment{
			{
				ID:            "ra-1",
				PrincipalID:   "sp-1",
				PrincipalType: "ServicePrincipal",
				PrincipalName: "Some Automation SP",
				RoleID:        "ai-admin",
			},
		},
		AzureServicePrincipals: []types.ServicePrincipal{
			{ID: "sp-1", AppID: "00000000-1111-2222-3333-444444444444", DisplayName: "Some Automation SP"},
		},
	}
	got := BuildAIAgentRolesSummary(d, nil, "test")
	a := got.Assignments[0]
	if a.Principal.AppID != "00000000-1111-2222-3333-444444444444" {
		t.Errorf("AppID = %q, want resolved from AzureServicePrincipals", a.Principal.AppID)
	}
	// SP is not a "human"
	if got.ExpandedHumanCount != 0 {
		t.Errorf("ExpandedHumanCount = %d, want 0 (SP not human)", got.ExpandedHumanCount)
	}
}

func TestBuildAIAgentRolesSummary_GroupExpansionFailedNilCache(t *testing.T) {
	d := &DetectorData{
		AzureDirectoryRoles: []types.DirectoryRole{
			{ID: "agent-id-admin", DisplayName: "Agent ID Administrator"},
		},
		AzureRoleAssignments: []types.RoleAssignment{
			{
				ID:            "ra-1",
				PrincipalID:   "group-1",
				PrincipalType: "Group",
				PrincipalName: "Mystery Group",
				RoleID:        "agent-id-admin",
			},
		},
	}
	// groupMembers is empty → expansion failed silently for this group
	got := BuildAIAgentRolesSummary(d, map[string][]types.GroupMember{}, "test")
	if got.TotalAssignments != 1 {
		t.Errorf("TotalAssignments = %d, want 1", got.TotalAssignments)
	}
	a := got.Assignments[0]
	if a.ExpandedMembers != nil {
		t.Errorf("ExpandedMembers should be nil when expansion failed, got %v", a.ExpandedMembers)
	}
	if a.ExpandedMembersCount != 0 {
		t.Errorf("ExpandedMembersCount = %d, want 0", a.ExpandedMembersCount)
	}
	if got.ExpandedHumanCount != 0 {
		t.Errorf("ExpandedHumanCount = %d, want 0 (no expansion data)", got.ExpandedHumanCount)
	}
}

func TestBuildAIAgentRolesSummary_GroupMembersTypeFilter(t *testing.T) {
	// A group containing 1 user + 1 service principal + 1 nested group
	// (Graph transitiveMembers returns these flat). Only the user counts
	// toward ExpandedHumanCount.
	d := &DetectorData{
		AzureDirectoryRoles: []types.DirectoryRole{
			{ID: "agent-id-admin", DisplayName: "Agent ID Administrator"},
		},
		AzureRoleAssignments: []types.RoleAssignment{
			{
				ID:            "ra-1",
				PrincipalID:   "group-1",
				PrincipalType: "Group",
				RoleID:        "agent-id-admin",
			},
		},
	}
	groupMembers := map[string][]types.GroupMember{
		"group-1": {
			{ID: "u-1", Type: "user"},
			{ID: "sp-1", Type: "servicePrincipal"},
			{ID: "g-2", Type: "group"},
		},
	}
	got := BuildAIAgentRolesSummary(d, groupMembers, "test")
	if got.ExpandedHumanCount != 1 {
		t.Errorf("ExpandedHumanCount = %d, want 1 (user only)", got.ExpandedHumanCount)
	}
	if got.Assignments[0].ExpandedMembersCount != 3 {
		t.Errorf("ExpandedMembersCount = %d, want 3 (raw count includes all types)", got.Assignments[0].ExpandedMembersCount)
	}
}

func TestBuildAIAgentRolesSummary_PIMOnlyAssignments(t *testing.T) {
	// On the live pilot tenant, AI Administrator assignments only show up
	// in /roleAssignmentSchedules (data.AzurePIMAssignments), NOT in
	// /roleAssignments (data.AzureRoleAssignments). The helper must walk
	// both sources to surface these.
	upn1 := "alice@t.com"
	upn2 := "bob@t.com"
	d := &DetectorData{
		AzureDirectoryRoles: []types.DirectoryRole{
			{ID: "ai-admin", DisplayName: "AI Administrator"},
		},
		// Empty — PIM assignments aren't here
		AzureRoleAssignments: nil,
		AzurePIMAssignments: &types.PIMAssignmentsSummary{
			Active: types.PIMActiveSummary{
				ByRole: map[string][]types.PIMAssignmentEntry{
					"AI Administrator": {
						{PrincipalID: "u1", PrincipalUpn: upn1, PrincipalName: "Alice", AssignmentType: "Assigned", DirectoryScopeID: "/"},
						{PrincipalID: "u2", PrincipalUpn: upn2, PrincipalName: "Bob", AssignmentType: "Assigned", DirectoryScopeID: "/"},
					},
				},
			},
		},
	}
	got := BuildAIAgentRolesSummary(d, nil, "test")
	if got.TotalAssignments != 2 {
		t.Errorf("TotalAssignments = %d, want 2", got.TotalAssignments)
	}
	if got.ActiveAssignments != 2 {
		t.Errorf("ActiveAssignments = %d, want 2", got.ActiveAssignments)
	}
	if got.ExpandedHumanCount != 2 {
		t.Errorf("ExpandedHumanCount = %d, want 2", got.ExpandedHumanCount)
	}
	if got.Assignments[0].AssignmentSource != "pim" {
		t.Errorf("PIM-only assignment source = %q, want pim", got.Assignments[0].AssignmentSource)
	}
}

func TestBuildAIAgentRolesSummary_DedupAcrossRoleAssignmentsAndPIM(t *testing.T) {
	// If the SAME (principal, role, scope) tuple shows up in both
	// AzureRoleAssignments and AzurePIMAssignments, count it once.
	d := &DetectorData{
		AzureDirectoryRoles: []types.DirectoryRole{
			{ID: "ai-admin", DisplayName: "AI Administrator"},
		},
		AzureRoleAssignments: []types.RoleAssignment{
			{
				ID:                "ra-1",
				PrincipalID:       "u-alice",
				PrincipalType:     "User",
				UserPrincipalName: "alice@t.com",
				RoleID:            "ai-admin",
				DirectoryScopeID:  "/",
			},
		},
		AzurePIMAssignments: &types.PIMAssignmentsSummary{
			Active: types.PIMActiveSummary{
				ByRole: map[string][]types.PIMAssignmentEntry{
					"AI Administrator": {
						{PrincipalID: "u-alice", PrincipalUpn: "alice@t.com", AssignmentType: "Assigned", DirectoryScopeID: "/"},
					},
				},
			},
		},
	}
	got := BuildAIAgentRolesSummary(d, nil, "test")
	if got.TotalAssignments != 1 {
		t.Errorf("TotalAssignments = %d, want 1 (deduped)", got.TotalAssignments)
	}
	if got.ExpandedHumanCount != 1 {
		t.Errorf("ExpandedHumanCount = %d, want 1", got.ExpandedHumanCount)
	}
}

func TestBuildAIAgentRolesSummary_RolesMonitoredSorted(t *testing.T) {
	d := &DetectorData{
		AzureDirectoryRoles: []types.DirectoryRole{
			{ID: "ai-admin", DisplayName: "AI Administrator"},
			{ID: "ai-reader", DisplayName: "AI Reader"},
			{ID: "agent-id-admin", DisplayName: "Agent ID Administrator"},
		},
	}
	got := BuildAIAgentRolesSummary(d, nil, "test")
	if len(got.RolesMonitored) != 3 {
		t.Fatalf("len(RolesMonitored) = %d, want 3", len(got.RolesMonitored))
	}
	if got.RolesMonitored[0] != "AI Administrator" {
		t.Errorf("first sorted = %q, want AI Administrator", got.RolesMonitored[0])
	}
	if got.RolesMonitored[2] != "Agent ID Administrator" {
		t.Errorf("third sorted = %q, want Agent ID Administrator", got.RolesMonitored[2])
	}
}
