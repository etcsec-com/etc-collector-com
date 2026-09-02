// Package types — Agent ID / AI / Copilot role assignments (v3.1.37 §3).
//
// Silverfort published a March 2026 advisory on the Entra "Agent ID
// Administrator" role: it has a documented scope flaw that lets a holder
// pivot to other privileged roles via the agents they manage, and 99% of
// audited tenants are exposed because the role is often assigned via
// implicit group nesting (e.g. "All Cloud Admins" group inherited the
// role automatically).
//
// This file defines the SaaS-facing shape of audit.aiAgentRoles, which
// answers "who has the AI/Agent admin roles in this tenant?" with
// per-assignment detail + group-membership expansion (so a 3-member
// "Cloud Admins" group counts as 3 humans, not 1 assignment).
//
// The collector ships only data — no findings. The SaaS analyzer derives
// AGENT_ID_ADMIN_OVER_ASSIGNED (critical, expandedHumanCount > 5),
// AGENT_ID_ADMIN_VIA_GROUP (high), AGENT_ID_ADMIN_PERMANENT (high).

package types

import "time"

// AIAgentRolesSummary captures the assignments to AI-related Entra roles
// (Agent ID Administrator, Agent ID Developer, AI Administrator, AI Reader,
// future Copilot* / Knowledge* roles). Filtering happens by displayName
// prefix at runtime so newly-introduced AI roles are picked up without a
// rebuild.
type AIAgentRolesSummary struct {
	// Available: false when GetDirectoryRoles failed or RoleAssignments
	// couldn't be collected. Reason carries a short diagnostic. Other
	// fields are zeroed in that case.
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`

	// RolesMonitored is the list of role displayNames that matched the
	// AI/Agent/Copilot/Knowledge filter on this audit. Empty array means
	// "we filtered, found none" (different from Available=false). Useful
	// for auditor traceability — exactly which roles applied to this
	// verdict.
	RolesMonitored []string `json:"rolesMonitored"`

	// Counters. ExpandedHumanCount is the dedup-ed set of distinct user
	// principalIDs reachable via direct User assignments + Group
	// transitiveMembers expansion (group membership flattened, SPs and
	// nested groups excluded — only humans). Powers the SaaS
	// "X people have AI admin power" headline.
	TotalAssignments      int `json:"totalAssignments"`
	ActiveAssignments     int `json:"activeAssignments"`
	EligibleAssignments   int `json:"eligibleAssignments"`
	GroupAssignmentsCount int `json:"groupAssignmentsCount"`
	ExpandedHumanCount    int `json:"expandedHumanCount"`

	Assignments []AIAgentRoleAssignment `json:"assignments"`

	// CollectorVersion is embedded so an audit JSON traces back to the
	// binary version that emitted the verdict (the role displayName
	// filter prefixes might evolve over releases as Microsoft adds
	// roles).
	CollectorVersion string `json:"collectorVersion,omitempty"`
}

// AIAgentRoleAssignment is one resolved role assignment. Source field
// distinguishes how the principal got the role: direct (assignment
// targets the user explicitly), group (the principal is a Group whose
// members inherit), pim (the principal got it via a PIM activated
// schedule).
type AIAgentRoleAssignment struct {
	RoleDefinitionID         string               `json:"roleDefinitionId"`
	RoleDefinitionName       string               `json:"roleDefinitionName"`
	PrincipalID              string               `json:"principalId"`
	PrincipalType            string               `json:"principalType"` // User | Group | ServicePrincipal
	Principal                AIAgentRolePrincipal `json:"principal"`
	DirectoryScopeID         string               `json:"directoryScopeId,omitempty"`
	AssignmentType           string               `json:"assignmentType"`   // active | eligible
	AssignmentSource         string               `json:"assignmentSource"` // direct | group | pim
	CreatedDateTime          *time.Time           `json:"createdDateTime,omitempty"`
	ExpandedMembers          []GroupMember        `json:"expandedMembers,omitempty"`
	ExpandedMembersCount     int                  `json:"expandedMembersCount,omitempty"`
	ExpandedMembersTruncated bool                 `json:"expandedMembersTruncated,omitempty"`
}

// AIAgentRolePrincipal is the resolved principal carrying the role.
// Different fields are populated based on PrincipalType:
//   - User: DisplayName + UserPrincipalName
//   - Group: DisplayName (members in ExpandedMembers on the parent assignment)
//   - ServicePrincipal: DisplayName + AppID
type AIAgentRolePrincipal struct {
	DisplayName       string `json:"displayName,omitempty"`
	UserPrincipalName string `json:"userPrincipalName,omitempty"`
	AppID             string `json:"appId,omitempty"`
}

// GroupMember is one entry from /groups/{id}/transitiveMembers. Type
// reflects the @odata.type from Graph (user | group | servicePrincipal),
// flattened for the SaaS analyzer. Group members are returned by Graph as
// transitive — nested groups are pre-flattened on Graph's side, so a
// GroupMember with Type="user" is a real human reachable via the chain.
type GroupMember struct {
	ID                string `json:"id"`
	Type              string `json:"type"` // user | group | servicePrincipal | unknown
	DisplayName       string `json:"displayName,omitempty"`
	UserPrincipalName string `json:"userPrincipalName,omitempty"`
}
