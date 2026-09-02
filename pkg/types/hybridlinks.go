// Package types — Hybrid edges Entra ↔ AD (v3.1.38 §2).
//
// Lands at audit.hybridLinks. Powers KPI #17 — the SaaS Hybrid Attack
// Paths Visualizer needs three categories of links to construct paths
// like "user AD compromis → user Entra synced → admin role Entra →
// tenant takeover" or "computer AD Tier-0 → HAJ device Entra → access
// to Entra resources" (BloodHound OpenGraph 2026 pattern).
//
// The collector ships data only — no findings. The SaaS analyzer derives
// HYBRID_PATH_PRIVILEGED_SYNC (critical), HYBRID_PATH_HAJ_TIER0 (high),
// HYBRID_FEDERATED_TRUST_RISKY (medium) by correlating this payload with
// the AD audit (attack_graph) of the same network.

package types

import "time"

// HybridLinksSummary is the SaaS-facing rollup. Three sections:
//   - syncStats: high-level counts (totalUsers / syncedFromAd / cloudOnly)
//     so the UI can render "X% of users are syncé from on-prem"
//   - syncedUsers[]: per-user detail with the on-prem identifiers needed
//     to cross-ref against an AD audit (DistinguishedName + SID +
//     SamAccountName + ImmutableId) plus admin-role enrichment for
//     prioritisation
//   - devices: total + counts per trustType + the slice of HAJ devices
//     (the only category that's actually a hybrid bridge)
//   - federatedTrusts[]: per-partner trust summary with isHighRisk flag
type HybridLinksSummary struct {
	// Available is false when neither user data nor device data nor
	// crossTenantAccess data was collected (e.g. all 3 sources failed
	// upstream). Reason carries why.
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`

	SyncStats       HybridSyncStats        `json:"syncStats"`
	SyncedUsers     []HybridSyncedUser     `json:"syncedUsers"`
	Devices         HybridDevices          `json:"devices"`
	FederatedTrusts []HybridFederatedTrust `json:"federatedTrusts"`

	// CollectorVersion is embedded for auditor traceability.
	CollectorVersion string `json:"collectorVersion,omitempty"`
}

// HybridSyncStats — top-level counts for the sync state.
type HybridSyncStats struct {
	TotalUsers   int  `json:"totalUsers"`
	SyncedFromAd int  `json:"syncedFromAd"`
	CloudOnly    int  `json:"cloudOnly"`
	SyncEnabled  bool `json:"syncEnabled"` // true when at least one user has OnPremisesSyncEnabled=true
}

// HybridSyncedUser captures one user that exists in both AD and Entra.
// All onPremises fields are populated from the Graph response (they're
// nil for cloud-only users). isAdmin + adminRoles[] are enriched from
// data.AzureRoleAssignments (privileged subset) so the SaaS analyzer
// can flag the high-value targets for hybrid attack paths.
type HybridSyncedUser struct {
	ID                           string   `json:"id"`
	UserPrincipalName            string   `json:"userPrincipalName,omitempty"`
	OnPremisesDistinguishedName  string   `json:"onPremisesDistinguishedName,omitempty"`
	OnPremisesSecurityIdentifier string   `json:"onPremisesSecurityIdentifier,omitempty"`
	OnPremisesImmutableID        string   `json:"onPremisesImmutableId,omitempty"`
	OnPremisesSamAccountName     string   `json:"onPremisesSamAccountName,omitempty"`
	SyncEnabled                  bool     `json:"syncEnabled"`
	IsAdmin                      bool     `json:"isAdmin"`
	AdminRoles                   []string `json:"adminRoles,omitempty"`
}

// HybridDevices captures the device landscape — the breakdown by
// trustType lets the SaaS UI show "X HAJ / Y cloud-only / Z Workplace".
// hajDevices[] carries the full list of Hybrid Azure AD Joined devices
// (TrustType=ServerAd) since those are the actual hybrid bridges
// pen-testers care about.
type HybridDevices struct {
	TotalDevices        int               `json:"totalDevices"`
	AzureAdJoined       int               `json:"azureAdJoined"`       // TrustType=AzureAd (cloud-only)
	HybridAzureAdJoined int               `json:"hybridAzureAdJoined"` // TrustType=ServerAd (HAJ)
	WorkplaceJoined     int               `json:"workplaceJoined"`     // TrustType=Workplace (BYOD)
	UnknownTrustType    int               `json:"unknownTrustType,omitempty"`
	HajDevices          []HybridHAJDevice `json:"hajDevices"`
	Truncated           bool              `json:"truncated,omitempty"` // pagination hit the cap
}

// HybridHAJDevice — one Hybrid Azure AD Joined device. The SaaS analyzer
// cross-refs DeviceID with the AD audit's Computer.objectGUID to
// reconstruct the Tier-0 device → HAJ → Entra access path.
type HybridHAJDevice struct {
	ID                    string     `json:"id"`
	DeviceID              string     `json:"deviceId"`
	DisplayName           string     `json:"displayName,omitempty"`
	TrustType             string     `json:"trustType"` // always "ServerAd" in this slice
	OperatingSystem       string     `json:"operatingSystem,omitempty"`
	OnPremisesSyncEnabled *bool      `json:"onPremisesSyncEnabled,omitempty"`
	AccountEnabled        *bool      `json:"accountEnabled,omitempty"`
	ApproximateLastSignIn *time.Time `json:"approximateLastSignIn,omitempty"`
}

// HybridFederatedTrust captures one cross-tenant partner with the
// classification flag. Sourced from data.AzureCrossTenantAccess.Partners
// (already collected v3.1.30 §5) — pure derivation, no new Graph call.
//
// isHighRisk is true when the partner is configured in a way that lets
// users from the foreign tenant pivot into our resources (heuristic per
// spec: MFA accepted from partner AND B2B Direct Connect inbound users
// allowed). The SaaS analyzer surfaces these as
// HYBRID_FEDERATED_TRUST_RISKY findings.
type HybridFederatedTrust struct {
	TenantID          string `json:"tenantId"`
	DisplayName       string `json:"displayName,omitempty"`
	IsServiceProvider bool   `json:"isServiceProvider,omitempty"`
	IsMfaAccepted     bool   `json:"isMfaAccepted"`
	B2BCollaboration  bool   `json:"b2bCollaboration"`
	B2BDirectConnect  bool   `json:"b2bDirectConnect"`
	IsHighRisk        bool   `json:"isHighRisk"`
}
