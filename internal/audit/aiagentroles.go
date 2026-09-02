// Package audit — AI agent role assignments rollup (v3.1.37 §3).
//
// Pure post-collection aggregator. Filters the role definitions and
// assignments already in DetectorData for the AI / Agent / Copilot /
// Knowledge family, dedups humans across direct + group assignments, and
// surfaces the result at audit.aiAgentRoles.
//
// Group transitive expansion is performed UPSTREAM in
// engine.collectAzureData (Graph roundtrip per Group principal) and the
// resulting member maps are passed in as `groupMembers`. This file does
// NO I/O — it's deterministic for a given (DetectorData, groupMembers)
// pair, which makes it trivially testable.
//
// Filter is name-prefix based so newly-introduced AI roles get picked up
// automatically when Microsoft adds them.

package audit

import (
	"sort"
	"strings"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// isAIAgentRole returns true when the displayName matches the AI / Agent /
// Copilot / Knowledge family. Future-proof: when Microsoft introduces
// "Copilot Studio Administrator" or "Knowledge Curator", this picks them
// up without a code change.
func isAIAgentRole(displayName string) bool {
	n := strings.TrimSpace(displayName)
	if n == "" {
		return false
	}
	lower := strings.ToLower(n)
	switch {
	case strings.HasPrefix(n, "Agent "):
		return true
	case strings.HasPrefix(n, "AI "):
		return true
	case strings.Contains(lower, "copilot"):
		return true
	case strings.Contains(lower, "knowledge admin") || strings.Contains(lower, "knowledge curator") || strings.Contains(lower, "knowledge manager"):
		// Knowledge* roles relate to Copilot grounding data — same exposure
		// as Agent ID Admin per Silverfort's advisory. Narrow allowlist
		// (rather than all "knowledge*" — too broad).
		return true
	}
	return false
}

// filterAIRoleIDs walks the directory roles and returns
// (ids matching the AI filter, sorted displayNames). Helper for engine
// wiring (which needs the IDs to subset RoleAssignments) and the helper
// itself (which needs the names for RolesMonitored).
func filterAIRoleIDs(roles []types.DirectoryRole) (map[string]string, []string) {
	idToName := make(map[string]string)
	for i := range roles {
		r := &roles[i]
		if isAIAgentRole(r.DisplayName) {
			idToName[r.ID] = r.DisplayName
		}
	}
	names := make([]string, 0, len(idToName))
	for _, n := range idToName {
		names = append(names, n)
	}
	sort.Strings(names)
	return idToName, names
}

// BuildAIAgentRolesSummary aggregates AI-related role assignments into the
// SaaS-facing payload. groupMembers maps groupID → already-expanded
// members (nil entry means "expansion was attempted but failed, e.g.
// missing Group.Read.All — show the assignment but no member list").
//
// version is the collector binary version (passed by the engine for
// auditor traceability — same pattern as v3.1.37 §1 baselineSecurity).
func BuildAIAgentRolesSummary(data *DetectorData, groupMembers map[string][]types.GroupMember, version string) *types.AIAgentRolesSummary {
	if data == nil {
		return nil
	}
	roleIDToName, monitored := filterAIRoleIDs(data.AzureDirectoryRoles)
	summary := &types.AIAgentRolesSummary{
		Available:        true,
		RolesMonitored:   monitored,
		Assignments:      []types.AIAgentRoleAssignment{},
		CollectorVersion: version,
	}
	if len(roleIDToName) == 0 {
		// Tenant has no AI/Agent role definitions — feature not yet
		// propagated or directly unsupported. Different from Available=false:
		// we *did* collect roles, just none matched.
		return summary
	}

	// Build SP lookup so we can resolve appId for ServicePrincipal principals.
	spByID := make(map[string]*types.ServicePrincipal, len(data.AzureServicePrincipals))
	for i := range data.AzureServicePrincipals {
		sp := &data.AzureServicePrincipals[i]
		spByID[sp.ID] = sp
	}

	// Distinct user principal IDs reachable via the AI roles (direct User
	// assignments + Group transitiveMembers of type=user). Used for the
	// "expandedHumanCount" headline. Tracked as a set keyed by principal
	// id so a user assigned both directly and via a group is counted once.
	humans := make(map[string]struct{})

	for i := range data.AzureRoleAssignments {
		ra := &data.AzureRoleAssignments[i]
		roleName, ok := roleIDToName[ra.RoleID]
		if !ok {
			continue
		}
		out := types.AIAgentRoleAssignment{
			RoleDefinitionID:   ra.RoleID,
			RoleDefinitionName: roleName,
			PrincipalID:        ra.PrincipalID,
			PrincipalType:      ra.PrincipalType,
			DirectoryScopeID:   ra.DirectoryScopeID,
		}
		if !ra.CreatedDateTime.IsZero() {
			t := ra.CreatedDateTime
			out.CreatedDateTime = &t
		}

		// AssignmentType: active vs eligible. RoleAssignment.IsEligible was
		// populated by the provider via the eligibility schedule cross-ref.
		if ra.IsEligible {
			out.AssignmentType = "eligible"
			summary.EligibleAssignments++
		} else {
			out.AssignmentType = "active"
			summary.ActiveAssignments++
		}

		// AssignmentSource:
		//   - pim: was eligible AND went through PIM activation
		//     (provider sets AssignmentType="activated" for that case)
		//   - group: principal is a Group (membership-derived)
		//   - direct: everything else (user/SP got the role explicitly)
		switch {
		case strings.EqualFold(ra.AssignmentType, "activated"):
			out.AssignmentSource = "pim"
		case strings.EqualFold(ra.PrincipalType, "Group"):
			out.AssignmentSource = "group"
			summary.GroupAssignmentsCount++
		default:
			out.AssignmentSource = "direct"
		}

		// Resolve principal display fields. The provider already enriched
		// User-type assignments with UserPrincipalName + display info; SP
		// resolution requires the lookup map.
		switch strings.ToLower(ra.PrincipalType) {
		case "user":
			out.Principal.DisplayName = ra.PrincipalName
			out.Principal.UserPrincipalName = ra.UserPrincipalName
			if ra.PrincipalID != "" {
				humans[ra.PrincipalID] = struct{}{}
			}
		case "serviceprincipal":
			out.Principal.DisplayName = ra.PrincipalName
			if sp, ok := spByID[ra.PrincipalID]; ok {
				if out.Principal.DisplayName == "" {
					out.Principal.DisplayName = sp.DisplayName
				}
				out.Principal.AppID = sp.AppID
			}
		case "group":
			out.Principal.DisplayName = ra.PrincipalName
			// Expansion: groupMembers is upstream-cached. nil entry means
			// expansion failed (e.g. missing Group.Read.All) — leave
			// ExpandedMembers empty so SaaS can flag.
			members, ok := groupMembers[ra.PrincipalID]
			if ok && members != nil {
				out.ExpandedMembers = members
				out.ExpandedMembersCount = len(members)
				// Truncated flag is signalled separately by the engine via
				// a sentinel — for v1 we skip surfacing truncation per-
				// assignment (the count remains accurate via cap=1000).
				for _, m := range members {
					if strings.EqualFold(m.Type, "user") && m.ID != "" {
						humans[m.ID] = struct{}{}
					}
				}
			}
		default:
			out.Principal.DisplayName = ra.PrincipalName
		}

		summary.Assignments = append(summary.Assignments, out)
		summary.TotalAssignments++
	}

	// PIM-only assignments. The /roleAssignments endpoint only returns
	// non-PIM assignments — anything managed through PIM (Active assigned,
	// Activated, or Eligible) lives in /roleAssignmentSchedules and lands
	// in data.AzurePIMAssignments. Tenants commonly assign AI admin roles
	// through PIM, so without this path the rollup misses most assignments.
	if data.AzurePIMAssignments != nil {
		// Reverse lookup roleDisplayName → roleID using the AI-filtered set.
		nameToID := make(map[string]string, len(roleIDToName))
		for id, name := range roleIDToName {
			nameToID[name] = id
		}
		// Dedup against assignments already emitted from AzureRoleAssignments.
		seen := make(map[string]struct{}, len(summary.Assignments))
		for i := range summary.Assignments {
			a := &summary.Assignments[i]
			seen[a.PrincipalID+"|"+a.RoleDefinitionID+"|"+a.DirectoryScopeID] = struct{}{}
		}
		emitPIM := func(roleName string, entries []types.PIMAssignmentEntry, isEligible bool) {
			roleID, ok := nameToID[roleName]
			if !ok {
				return
			}
			for i := range entries {
				e := &entries[i]
				key := e.PrincipalID + "|" + roleID + "|" + e.DirectoryScopeID
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}

				out := types.AIAgentRoleAssignment{
					RoleDefinitionID:   roleID,
					RoleDefinitionName: roleName,
					PrincipalID:        e.PrincipalID,
					DirectoryScopeID:   e.DirectoryScopeID,
				}
				out.PrincipalType = inferPrincipalTypeFromPIMEntry(e, spByID)
				if e.CreatedDateTime != nil {
					out.CreatedDateTime = e.CreatedDateTime
				}
				if isEligible {
					out.AssignmentType = "eligible"
					summary.EligibleAssignments++
				} else {
					out.AssignmentType = "active"
					summary.ActiveAssignments++
				}
				switch {
				case strings.EqualFold(e.AssignmentType, "Activated"):
					out.AssignmentSource = "pim"
				case strings.EqualFold(out.PrincipalType, "Group"):
					out.AssignmentSource = "group"
					summary.GroupAssignmentsCount++
				default:
					// Default: PIM-managed assignments (Assigned/Eligible) are
					// considered "pim" source — they're not direct cluster
					// assignments. SaaS analyzer can read AssignmentType for
					// finer detail (eligible vs active).
					out.AssignmentSource = "pim"
				}
				switch strings.ToLower(out.PrincipalType) {
				case "user":
					out.Principal.DisplayName = e.PrincipalName
					out.Principal.UserPrincipalName = e.PrincipalUpn
					if e.PrincipalID != "" {
						humans[e.PrincipalID] = struct{}{}
					}
				case "serviceprincipal":
					out.Principal.DisplayName = e.PrincipalName
					if sp, ok := spByID[e.PrincipalID]; ok {
						if out.Principal.DisplayName == "" {
							out.Principal.DisplayName = sp.DisplayName
						}
						out.Principal.AppID = sp.AppID
					}
				case "group":
					out.Principal.DisplayName = e.PrincipalName
					if members, ok := groupMembers[e.PrincipalID]; ok && members != nil {
						out.ExpandedMembers = members
						out.ExpandedMembersCount = len(members)
						for _, m := range members {
							if strings.EqualFold(m.Type, "user") && m.ID != "" {
								humans[m.ID] = struct{}{}
							}
						}
					}
				default:
					out.Principal.DisplayName = e.PrincipalName
				}
				summary.Assignments = append(summary.Assignments, out)
				summary.TotalAssignments++
			}
		}
		for roleName, entries := range data.AzurePIMAssignments.Active.ByRole {
			if !isAIAgentRole(roleName) {
				continue
			}
			emitPIM(roleName, entries, false)
		}
		for roleName, entries := range data.AzurePIMAssignments.Eligible.ByRole {
			if !isAIAgentRole(roleName) {
				continue
			}
			emitPIM(roleName, entries, true)
		}
	}

	summary.ExpandedHumanCount = len(humans)
	return summary
}

// inferPrincipalTypeFromPIMEntry — PIMAssignmentEntry doesn't expose
// principalType directly. We heuristic by checking PrincipalUpn (User has
// one), looking up the SP cache (ServicePrincipal), defaulting to Group
// otherwise. The dedup logic still works because the PIM data is
// orthogonal to AzureRoleAssignments on this tenant.
func inferPrincipalTypeFromPIMEntry(e *types.PIMAssignmentEntry, spByID map[string]*types.ServicePrincipal) string {
	if e.PrincipalUpn != "" {
		return "User"
	}
	if _, ok := spByID[e.PrincipalID]; ok {
		return "ServicePrincipal"
	}
	// PIMAssignmentEntry.MemberType: "Direct" | "Group" | "Inherited" — but
	// "Direct" doesn't tell us the principal kind. Default to User; if the
	// SaaS sees a User without a UPN it can flag.
	return "User"
}
