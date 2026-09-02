// Package audit — Hybrid edges Entra ↔ AD builder (v3.1.38 §2).
//
// Pure post-collection aggregator. Walks data.Users + data.AzureDevices +
// data.AzureRoleAssignments + data.AzureCrossTenantAccess (all already in
// memory) and produces audit.hybridLinks — the data layer the SaaS Hybrid
// Attack Paths Visualizer needs to construct paths like
//   user_AD_compromis → user_Entra_synced → admin_role_Entra → tenant_takeover
//
// The collector ships only data; SaaS analyzer derives findings
// (HYBRID_PATH_PRIVILEGED_SYNC, HYBRID_PATH_HAJ_TIER0,
// HYBRID_FEDERATED_TRUST_RISKY).

package audit

import (
	"strings"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// privilegedRoleIDs lists the Entra built-in directory roles considered
// "privileged" for hybrid-attack-path prioritisation.
//
// Source canonique : signin-events/helpers.go privilegedRoleIDs
// (v3.1.35 §3 IMPOSSIBLE_TRAVEL admin escalation). Kept in sync — when
// Microsoft adds a new high-privilege role, update both files. (TODO
// v3.1.40+: refactor into a shared package to remove this duplication.)
var hybridPrivilegedRoleIDs = map[string]bool{
	"62e90394-69f5-4237-9190-012177145e10": true, // Global Administrator
	"e8611ab8-c189-46e8-94e1-60213ab1f814": true, // Privileged Role Administrator
	"194ae4cb-b126-40b2-bd5b-6091b380977d": true, // Security Administrator
	"fe930be7-5e62-47db-91af-98c3a49a38b1": true, // User Administrator
	"c4e39bd9-1100-46d3-8c65-fb160da0071f": true, // Authentication Administrator
	"b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": true, // Conditional Access Administrator
	"29232cdf-9323-42fd-ade2-1d097af3e4de": true, // Exchange Administrator
	"f28a1f50-f6e7-4571-818b-6a12f2af6b6c": true, // SharePoint Administrator
	"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": true, // Application Administrator
	"158c047a-c907-4556-b7ef-446551a6b5f7": true, // Cloud Application Administrator
}

// buildUserAdminMap returns map[principalID][]roleNames for User-type
// principals that hold at least one role from hybridPrivilegedRoleIDs.
// Sorted by role name within each principal so the output is stable
// across audits (helps SaaS-side diffing).
func buildUserAdminMap(roleAssignments []types.RoleAssignment) map[string][]string {
	out := make(map[string][]string)
	for i := range roleAssignments {
		ra := &roleAssignments[i]
		if !strings.EqualFold(ra.PrincipalType, "User") {
			continue
		}
		if !hybridPrivilegedRoleIDs[ra.RoleID] {
			continue
		}
		// RoleName already enriched via $expand=roleDefinition during
		// collection (see GetRoleAssignments). Fallback to RoleID if for
		// some reason the enrichment didn't happen.
		name := ra.RoleName
		if name == "" {
			name = ra.RoleID
		}
		// Deduplicate: a user may have the same role at multiple scopes.
		exists := false
		for _, r := range out[ra.PrincipalID] {
			if r == name {
				exists = true
				break
			}
		}
		if !exists {
			out[ra.PrincipalID] = append(out[ra.PrincipalID], name)
		}
	}
	return out
}

// isHighRiskFederatedTrust returns true when a cross-tenant partner is
// configured to let foreign-tenant users pivot into our resources with
// minimal friction. Heuristic per spec: MFA accepted from partner AND
// B2B Direct Connect inbound users explicitly allowed.
func isHighRiskFederatedTrust(p *types.CrossTenantPartnerPolicy) bool {
	if p == nil {
		return false
	}
	if !p.InboundTrust.IsMfaAccepted {
		return false
	}
	return strings.EqualFold(p.B2BDirectConnect.Inbound.UsersAndGroups.AccessType, "allowed")
}

// b2bChannelEnabled returns true when the inbound channel of a B2B policy
// has at least one access target allowed (i.e. the partner can use the
// channel at all).
func b2bChannelEnabled(channels types.CrossTenantPolicyChannels) bool {
	if strings.EqualFold(channels.Inbound.UsersAndGroups.AccessType, "allowed") {
		return true
	}
	if strings.EqualFold(channels.Inbound.Applications.AccessType, "allowed") {
		return true
	}
	return false
}

// BuildHybridLinksSummary aggregates the hybrid links payload. devicesTruncated
// is propagated from the upstream GetDevices call; pass false when the call
// completed cleanly. Returns nil for fully-empty data so audit.hybridLinks is
// omitted from the JSON on trivially-empty tenants.
func BuildHybridLinksSummary(data *DetectorData, devicesTruncated bool, version string) *types.HybridLinksSummary {
	if data == nil {
		return nil
	}
	if len(data.Users) == 0 && len(data.AzureDevices) == 0 && data.AzureCrossTenantAccess == nil {
		return nil
	}

	summary := &types.HybridLinksSummary{
		Available:        true,
		CollectorVersion: version,
		SyncedUsers:      []types.HybridSyncedUser{},
		FederatedTrusts:  []types.HybridFederatedTrust{},
	}
	summary.Devices.HajDevices = []types.HybridHAJDevice{}

	// === Sync stats + per-user detail ===
	adminMap := buildUserAdminMap(data.AzureRoleAssignments)
	for i := range data.Users {
		u := &data.Users[i]
		// Heuristic: a User is "Azure-relevant" when it carries at least
		// the AzureUserType field (populated only on Azure provider
		// audits). For an AD-only audit data.Users contains AD users
		// without these fields and we skip them.
		if u.AzureUserType == nil && len(u.AzureAssignedLicenses) == 0 && u.AzureOnPremisesSyncEnabled == nil {
			continue
		}
		summary.SyncStats.TotalUsers++
		synced := u.AzureOnPremisesSyncEnabled != nil && *u.AzureOnPremisesSyncEnabled
		if synced {
			summary.SyncStats.SyncedFromAd++
		} else {
			summary.SyncStats.CloudOnly++
		}
		if !synced {
			continue
		}
		// Azure user ID is stashed in User.ObjectSID by convertAzureUser
		// (a generic "object identifier" slot used as SID for AD and as
		// the Entra GUID for Azure users — same field, different
		// semantics per provider).
		entry := types.HybridSyncedUser{
			ID:                u.ObjectSID,
			UserPrincipalName: u.UserPrincipalName,
			SyncEnabled:       true,
		}
		if u.AzureOnPremisesDistinguishedName != nil {
			entry.OnPremisesDistinguishedName = *u.AzureOnPremisesDistinguishedName
		}
		if u.AzureOnPremisesSecurityIdentifier != nil {
			entry.OnPremisesSecurityIdentifier = *u.AzureOnPremisesSecurityIdentifier
		}
		if u.AzureOnPremisesImmutableID != nil {
			entry.OnPremisesImmutableID = *u.AzureOnPremisesImmutableID
		}
		if u.AzureOnPremisesSamAccountName != nil {
			entry.OnPremisesSamAccountName = *u.AzureOnPremisesSamAccountName
		}
		if roles, ok := adminMap[entry.ID]; ok && len(roles) > 0 {
			entry.IsAdmin = true
			entry.AdminRoles = roles
		}
		summary.SyncedUsers = append(summary.SyncedUsers, entry)
	}
	summary.SyncStats.SyncEnabled = summary.SyncStats.SyncedFromAd > 0

	// === Devices breakdown ===
	for i := range data.AzureDevices {
		d := &data.AzureDevices[i]
		summary.Devices.TotalDevices++
		switch strings.ToLower(d.TrustType) {
		case "azuread":
			summary.Devices.AzureAdJoined++
		case "serverad":
			summary.Devices.HybridAzureAdJoined++
			summary.Devices.HajDevices = append(summary.Devices.HajDevices, types.HybridHAJDevice{
				ID:                    d.ID,
				DeviceID:              d.DeviceID,
				DisplayName:           d.DisplayName,
				TrustType:             d.TrustType,
				OperatingSystem:       d.OperatingSystem,
				OnPremisesSyncEnabled: d.OnPremisesSyncEnabled,
				AccountEnabled:        d.AccountEnabled,
				ApproximateLastSignIn: d.ApproximateLastSignIn,
			})
		case "workplace":
			summary.Devices.WorkplaceJoined++
		default:
			summary.Devices.UnknownTrustType++
		}
	}
	summary.Devices.Truncated = devicesTruncated

	// === Federated trusts ===
	if data.AzureCrossTenantAccess != nil {
		for i := range data.AzureCrossTenantAccess.Partners {
			p := &data.AzureCrossTenantAccess.Partners[i]
			ft := types.HybridFederatedTrust{
				TenantID:          p.TenantID,
				DisplayName:       p.DisplayName,
				IsServiceProvider: p.IsServiceProvider,
				IsMfaAccepted:     p.InboundTrust.IsMfaAccepted,
				B2BCollaboration:  b2bChannelEnabled(p.B2BCollaboration),
				B2BDirectConnect:  b2bChannelEnabled(p.B2BDirectConnect),
				IsHighRisk:        isHighRiskFederatedTrust(p),
			}
			summary.FederatedTrusts = append(summary.FederatedTrusts, ft)
		}
	}

	return summary
}
