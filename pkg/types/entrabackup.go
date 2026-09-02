// Package types — Microsoft Entra Backup status (v3.1.37 §2).
//
// Microsoft announced "Entra Backup & Recovery" in late 2025 — capability
// to backup/restore an Entra ID tenant (users, groups, roles, CA policies,
// app registrations, settings) for disaster recovery. As of v3.1.37
// (May 2026) the Microsoft Graph API for this feature is NOT YET GENERALLY
// AVAILABLE: probing all 12 candidate endpoints (admin/backup, identity/
// backup, security/backup namespaces under v1.0 and beta) returned HTTP 400
// "Resource not found for the segment 'backup'".
//
// This file ships the full schema in advance so the SaaS analyzer can
// ingest the payload without refactor when Microsoft eventually GAs the
// API and we activate the real probe in a future release. Until then, the
// collector emits Available=false with a populated Reason.

package types

import "time"

// EntraBackupStatus captures the configured state of Microsoft Entra
// Backup & Recovery for a tenant. Lands at audit.entraBackup.
//
// Two top-level booleans describe the situation precisely:
//   - Available: false → the Microsoft Graph API for Entra Backup itself
//     is not reachable (probe failed with 4xx, or the segment doesn't
//     exist yet in the Graph version this collector knows). The SaaS
//     should NOT emit a "backup disabled" finding in this case — emit a
//     warning-level "API not yet available" instead.
//   - Available: true && Enabled: false → the API works, the tenant has
//     not configured Entra Backup. SaaS should emit ENTRA_BACKUP_DISABLED
//     (severity critical) per the spec.
//   - Available: true && Enabled: true → real status; SaaS reads
//     LastSuccessfulBackup, RetentionDays, Scope to derive
//     ENTRA_BACKUP_STALE / ENTRA_BACKUP_PARTIAL_SCOPE findings.
type EntraBackupStatus struct {
	// Available is false when the Graph API for Entra Backup is not
	// reachable from this collector. Reason carries the diagnostic.
	// All other fields are meaningless when Available=false.
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`

	// Enabled, when Available=true, indicates whether the tenant has
	// configured Entra Backup at all. The remaining fields describe the
	// configuration when Enabled=true.
	Enabled         bool       `json:"enabled"`
	EnabledDateTime *time.Time `json:"enabledDateTime,omitempty"` // when the tenant first turned backup on

	Scope                 EntraBackupScope          `json:"scope"`
	RetentionDays         int                       `json:"retentionDays"`
	Frequency             string                    `json:"frequency,omitempty"` // daily | continuous | manual
	LastSuccessfulBackup  *time.Time                `json:"lastSuccessfulBackup,omitempty"`
	RestorePoints         []EntraBackupRestorePoint `json:"restorePoints"`
	EstimatedRecoveryTime string                    `json:"estimatedRecoveryTime,omitempty"`

	// Traceability fields — when did this collector probe Microsoft Graph,
	// and which collector binary version emitted the verdict. Useful when
	// SaaS sees Available=true appear in audits and wants to correlate
	// "Microsoft shipped the API around date X".
	ProbedAt         time.Time `json:"probedAt"`
	CollectorVersion string    `json:"collectorVersion,omitempty"`
}

// EntraBackupScope describes which Entra ID object types are included in
// the tenant's backup configuration. All-false on a tenant where backup
// is disabled or the API isn't available.
type EntraBackupScope struct {
	Users                     bool `json:"users"`
	Groups                    bool `json:"groups"`
	Roles                     bool `json:"roles"`
	ConditionalAccessPolicies bool `json:"conditionalAccessPolicies"`
	Applications              bool `json:"applications"`
	ServicePrincipals         bool `json:"servicePrincipals"`
	Settings                  bool `json:"settings"`
}

// EntraBackupRestorePoint describes one snapshot in the backup history.
// SaaS can compute "last successful backup" + "backup cadence" from the
// list (newest-first when populated by the provider).
type EntraBackupRestorePoint struct {
	ID              string                         `json:"id"`
	CreatedDateTime time.Time                      `json:"createdDateTime"`
	Status          string                         `json:"status"` // succeeded | failed | partial
	ScopeSummary    EntraBackupRestorePointSummary `json:"scopeSummary"`
	SizeInBytes     int64                          `json:"sizeInBytes,omitempty"`
}

// EntraBackupRestorePointSummary breaks down what was actually captured in
// a given restore point. Used by SaaS to detect drift: if scope.users=true
// but RestorePoints[0].ScopeSummary.UsersBackedUp=0, something failed
// silently and the SaaS should flag it.
type EntraBackupRestorePointSummary struct {
	UsersBackedUp             int `json:"usersBackedUp"`
	GroupsBackedUp            int `json:"groupsBackedUp"`
	RolesBackedUp             int `json:"rolesBackedUp"`
	PoliciesBackedUp          int `json:"policiesBackedUp"`
	ApplicationsBackedUp      int `json:"applicationsBackedUp"`
	ServicePrincipalsBackedUp int `json:"servicePrincipalsBackedUp"`
}
