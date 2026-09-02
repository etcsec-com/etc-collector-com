// Package types — Azure directory audit logs (v3.1.36).
//
// This file carries the structured shape of a single Azure AD / Entra
// directory audit event as returned by Graph /v1.0/auditLogs/directoryAudits,
// plus the per-tenant aggregator used to power the SaaS Identity Drift
// Timeline.
//
// Scope: only 5 security-relevant categories are collected — RoleManagement,
// ConditionalAccess, ApplicationManagement, GroupManagement, UserManagement.
// Authentication audits live under sign-in logs (separate collection),
// DirectoryManagement is too noisy, Other isn't useful.
//
// 90-day window matches quarterly compliance reviews (SOC 2, ANSSI, ISO).

package types

import "time"

// DirectoryAudit mirrors the Graph /v1.0/auditLogs/directoryAudits entry.
// Field selection covers the questions a RSSI / admin / auditor needs to
// answer: who did what, when, on which target, with what result.
type DirectoryAudit struct {
	ID                  string                           `json:"id"`
	ActivityDateTime    time.Time                        `json:"activityDateTime"`
	ActivityDisplayName string                           `json:"activityDisplayName"`
	Category            string                           `json:"category"` // RoleManagement | ConditionalAccess | ApplicationManagement | GroupManagement | UserManagement
	LoggedByService     string                           `json:"loggedByService,omitempty"`
	Result              string                           `json:"result,omitempty"`       // success | failure | timeout | unknownFutureValue
	ResultReason        string                           `json:"resultReason,omitempty"` // populated on failures
	CorrelationID       string                           `json:"correlationId,omitempty"`
	InitiatedBy         *DirectoryAuditInitiatedBy       `json:"initiatedBy,omitempty"`
	TargetResources     []DirectoryAuditTarget           `json:"targetResources,omitempty"`
	AdditionalDetails   []DirectoryAuditAdditionalDetail `json:"additionalDetails,omitempty"`
}

// DirectoryAuditInitiatedBy carries the actor — either a user (UPN +
// displayName populated) or an app/SP (appId + servicePrincipalId
// populated). Microsoft sets exactly one of the two on each event;
// we expose both fields as pointers so the consumer can distinguish.
type DirectoryAuditInitiatedBy struct {
	User *DirectoryAuditUserActor `json:"user,omitempty"`
	App  *DirectoryAuditAppActor  `json:"app,omitempty"`
}

type DirectoryAuditUserActor struct {
	ID                string `json:"id,omitempty"`
	UserPrincipalName string `json:"userPrincipalName,omitempty"`
	DisplayName       string `json:"displayName,omitempty"`
	IPAddress         string `json:"ipAddress,omitempty"` // sometimes populated when initiator was a human
}

type DirectoryAuditAppActor struct {
	AppID              string `json:"appId,omitempty"`
	DisplayName        string `json:"displayName,omitempty"`
	ServicePrincipalID string `json:"servicePrincipalId,omitempty"`
}

// DirectoryAuditTarget describes one resource affected by the audit event.
// A single event can touch multiple targets (e.g. assigning a role to a
// group hits both the group and the role definition).
type DirectoryAuditTarget struct {
	ID                 string                           `json:"id,omitempty"`
	DisplayName        string                           `json:"displayName,omitempty"`
	Type               string                           `json:"type,omitempty"`              // User | Group | Application | ServicePrincipal | Role | Policy | etc.
	UserPrincipalName  string                           `json:"userPrincipalName,omitempty"` // populated when Type==User
	GroupType          string                           `json:"groupType,omitempty"`         // populated when Type==Group
	ModifiedProperties []DirectoryAuditModifiedProperty `json:"modifiedProperties,omitempty"`
}

// DirectoryAuditModifiedProperty captures a before/after diff on a single
// attribute. Microsoft serialises old/new as JSON-encoded strings even when
// the underlying value is structured — we keep them as strings to preserve
// fidelity (the SaaS analyzer can json.Parse them on demand).
type DirectoryAuditModifiedProperty struct {
	DisplayName string `json:"displayName,omitempty"`
	OldValue    string `json:"oldValue,omitempty"`
	NewValue    string `json:"newValue,omitempty"`
}

// DirectoryAuditAdditionalDetail carries category-specific metadata
// (e.g. UserAgent, additional flags) as opaque key/value pairs.
type DirectoryAuditAdditionalDetail struct {
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
}

// DirectoryAuditsSummary is the aggregator emitted at audit.directoryAudits.
// Mirrors the shape of OAuthGrantsSummary / PIMActivationHistorySummary so
// the SaaS analyzer pipeline reads it the same way.
type DirectoryAuditsSummary struct {
	TotalEvents     int              `json:"totalEvents"`
	ByCategory      map[string]int   `json:"byCategory"`
	Truncated       bool             `json:"truncated,omitempty"`       // true when the budget cap stopped pagination early
	OldestCollected *time.Time       `json:"oldestCollected,omitempty"` // earliest activityDateTime in events[]
	NewestCollected *time.Time       `json:"newestCollected,omitempty"` // latest activityDateTime in events[]
	RequestedDays   int              `json:"requestedDays,omitempty"`   // operator-asked lookback (typically 90)
	ActualDays      int              `json:"actualDays,omitempty"`      // clamped or budget-truncated effective span
	Events          []DirectoryAudit `json:"events"`
}
