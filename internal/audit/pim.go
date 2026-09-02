package audit

import (
	"sort"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// BuildPIMAssignmentsSummary partitions role assignments into active +
// eligible groups, buckets each by role display name, and computes the
// "never activated" subset of eligibles (no selfActivate event in the
// 90-day history window).
//
// Inputs:
//   - schedules: from /roleManagement/directory/roleAssignmentSchedules
//     (carries assignmentType = Assigned | Activated)
//   - eligibles: from /roleManagement/directory/roleEligibilityScheduleInstances
//     (already shaped as a map by GetRoleEligibilitySchedules)
//   - history: from /roleManagement/directory/roleAssignmentScheduleRequests
//     (90-day window, used only to flag dormant eligibles)
//
// Returns a non-nil summary even when all inputs are empty so the SaaS
// dispatcher gets a stable shape ({active:{total:0,...}, eligible:{...}, neverActivated:[]}).
func BuildPIMAssignmentsSummary(
	schedules []types.RoleAssignment,
	eligibles map[string]types.RoleAssignment,
	history []types.PIMScheduleRequest,
) *types.PIMAssignmentsSummary {
	out := &types.PIMAssignmentsSummary{
		Active: types.PIMActiveSummary{
			ByAssignmentType: map[string]int{},
			ByRole:           map[string][]types.PIMAssignmentEntry{},
		},
		Eligible: types.PIMEligibleSummary{
			ByRole: map[string][]types.PIMAssignmentEntry{},
		},
	}

	// 1. Active = assignmentType in {Assigned, Activated} (case-insensitive
	//    match on the existing field). The legacy "direct" / "activated"
	//    lowercase values produced by GetRoleAssignments map to "Assigned"
	//    / "Activated" respectively.
	for i := range schedules {
		s := &schedules[i]
		atype := normalisedAssignmentType(s.AssignmentType)
		if atype != "Assigned" && atype != "Activated" {
			continue
		}
		entry := buildEntry(s, atype)
		out.Active.Total++
		out.Active.ByAssignmentType[atype]++
		out.Active.ByRole[s.RoleName] = append(out.Active.ByRole[s.RoleName], entry)
	}

	// 2. Eligible = values of the eligibility map.
	for _, e := range eligibles {
		entry := buildEntry(&e, "Eligible")
		out.Eligible.Total++
		out.Eligible.ByRole[e.RoleName] = append(out.Eligible.ByRole[e.RoleName], entry)
	}

	// 3. NeverActivated = eligibles where no selfActivate event in history
	//    matches {principalId, roleId}. Build a set first, then filter.
	activatedKey := make(map[string]struct{}, len(history))
	for _, h := range history {
		if h.Action != "selfActivate" {
			continue
		}
		activatedKey[h.PrincipalID+"|"+h.RoleID] = struct{}{}
	}
	for _, e := range eligibles {
		key := e.PrincipalID + "|" + e.RoleID
		if _, ok := activatedKey[key]; ok {
			continue
		}
		var since *time.Time
		if !e.StartDateTime.IsZero() {
			t := e.StartDateTime
			since = &t
		}
		out.NeverActivated = append(out.NeverActivated, types.PIMNeverActivatedEntry{
			PrincipalID:     e.PrincipalID,
			PrincipalUpn:    e.UserPrincipalName,
			PrincipalName:   e.PrincipalName,
			RoleDisplayName: e.RoleName,
			EligibleSince:   since,
			LastActivation:  nil, // explicit null per spec
		})
	}
	// Stable order so diffs between audits are readable.
	sort.Slice(out.NeverActivated, func(i, j int) bool {
		if out.NeverActivated[i].RoleDisplayName != out.NeverActivated[j].RoleDisplayName {
			return out.NeverActivated[i].RoleDisplayName < out.NeverActivated[j].RoleDisplayName
		}
		return out.NeverActivated[i].PrincipalUpn < out.NeverActivated[j].PrincipalUpn
	})
	return out
}

// BuildPIMActivationHistorySummary turns the raw schedule-requests slice
// into the audit.pimActivationHistory payload (counters + events). Events
// are passed through as-is so the SaaS analyzer keeps full detail
// (justification, ticketNumber, ticketSystem, completedDateTime).
func BuildPIMActivationHistorySummary(requests []types.PIMScheduleRequest) *types.PIMActivationHistorySummary {
	out := &types.PIMActivationHistorySummary{
		TotalRequests: len(requests),
		ByAction:      map[string]int{},
		Events:        requests,
	}
	for _, r := range requests {
		if r.Action != "" {
			out.ByAction[r.Action]++
		}
	}
	return out
}

// normalisedAssignmentType maps the lowercase legacy value used by
// GetRoleAssignments ("direct"/"activated"/"eligible") to the Graph
// canonical PascalCase used by /roleAssignmentSchedules ("Assigned"/
// "Activated"/"Eligible"). New PIM payloads should pass through unchanged.
func normalisedAssignmentType(s string) string {
	switch s {
	case "direct", "Direct", "Assigned":
		return "Assigned"
	case "activated", "Activated":
		return "Activated"
	case "eligible", "Eligible":
		return "Eligible"
	default:
		return s
	}
}

func buildEntry(ra *types.RoleAssignment, assignmentType string) types.PIMAssignmentEntry {
	out := types.PIMAssignmentEntry{
		PrincipalID:      ra.PrincipalID,
		PrincipalUpn:     ra.UserPrincipalName,
		PrincipalName:    ra.PrincipalName,
		AssignmentType:   assignmentType,
		MemberType:       ra.MemberType,
		DirectoryScopeID: ra.DirectoryScopeID,
	}
	if !ra.StartDateTime.IsZero() {
		t := ra.StartDateTime
		out.StartDateTime = &t
	}
	if !ra.EndDateTime.IsZero() {
		t := ra.EndDateTime
		out.EndDateTime = &t
	}
	if !ra.CreatedDateTime.IsZero() {
		t := ra.CreatedDateTime
		out.CreatedDateTime = &t
	}
	return out
}
