package audit

import (
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

func strPtr(s string) *string { return &s }
func boolPtr2(b bool) *bool   { return &b }

func mkAzureUser(id, upn string, syncEnabled *bool, dn, sid, sam, immutable *string) types.User {
	memberType := "Member"
	return types.User{
		ObjectSID:                         id,
		UserPrincipalName:                 upn,
		AzureUserType:                     &memberType,
		AzureOnPremisesSyncEnabled:        syncEnabled,
		AzureOnPremisesDistinguishedName:  dn,
		AzureOnPremisesSecurityIdentifier: sid,
		AzureOnPremisesSamAccountName:     sam,
		AzureOnPremisesImmutableID:        immutable,
	}
}

func mkDevice(id, deviceID, displayName, trustType, os string) types.AzureDevice {
	return types.AzureDevice{
		ID: id, DeviceID: deviceID, DisplayName: displayName,
		TrustType: trustType, OperatingSystem: os,
	}
}

func TestBuildHybridLinks_NilData(t *testing.T) {
	if got := BuildHybridLinksSummary(nil, false, "test"); got != nil {
		t.Errorf("expected nil for nil data, got %+v", got)
	}
}

func TestBuildHybridLinks_EmptyData_ReturnsNil(t *testing.T) {
	d := &DetectorData{}
	if got := BuildHybridLinksSummary(d, false, "test"); got != nil {
		t.Errorf("expected nil for empty data, got %+v", got)
	}
}

func TestBuildHybridLinks_SyncStatsAndCounts(t *testing.T) {
	tr := boolPtr2(true)
	fa := boolPtr2(false)
	d := &DetectorData{
		Users: []types.User{
			mkAzureUser("u-sync-admin", "alice@t.com", tr, strPtr("CN=alice,DC=corp,DC=local"), strPtr("S-1-5-21-1"), strPtr("alice"), strPtr("immut1")),
			mkAzureUser("u-sync-regular", "bob@t.com", tr, strPtr("CN=bob,DC=corp,DC=local"), strPtr("S-1-5-21-2"), strPtr("bob"), strPtr("immut2")),
			mkAzureUser("u-cloud-only", "carol@t.com", fa, nil, nil, nil, nil),
		},
		AzureRoleAssignments: []types.RoleAssignment{
			{
				PrincipalID:   "u-sync-admin",
				PrincipalType: "User",
				RoleID:        "62e90394-69f5-4237-9190-012177145e10", // Global Admin
				RoleName:      "Global Administrator",
			},
		},
	}
	got := BuildHybridLinksSummary(d, false, "test")
	if got == nil {
		t.Fatal("nil")
	}
	if got.SyncStats.TotalUsers != 3 {
		t.Errorf("TotalUsers = %d, want 3", got.SyncStats.TotalUsers)
	}
	if got.SyncStats.SyncedFromAd != 2 {
		t.Errorf("SyncedFromAd = %d, want 2", got.SyncStats.SyncedFromAd)
	}
	if got.SyncStats.CloudOnly != 1 {
		t.Errorf("CloudOnly = %d, want 1", got.SyncStats.CloudOnly)
	}
	if !got.SyncStats.SyncEnabled {
		t.Error("SyncEnabled should be true (2 synced users)")
	}
	if len(got.SyncedUsers) != 2 {
		t.Errorf("SyncedUsers len = %d, want 2", len(got.SyncedUsers))
	}
	// Admin lookup populated
	var adminEntry *types.HybridSyncedUser
	for i := range got.SyncedUsers {
		if got.SyncedUsers[i].ID == "u-sync-admin" {
			adminEntry = &got.SyncedUsers[i]
			break
		}
	}
	if adminEntry == nil {
		t.Fatal("admin user not in SyncedUsers")
	}
	if !adminEntry.IsAdmin {
		t.Error("admin user IsAdmin should be true")
	}
	if len(adminEntry.AdminRoles) != 1 || adminEntry.AdminRoles[0] != "Global Administrator" {
		t.Errorf("AdminRoles = %v, want [Global Administrator]", adminEntry.AdminRoles)
	}
	if adminEntry.OnPremisesDistinguishedName != "CN=alice,DC=corp,DC=local" {
		t.Errorf("DN propagation broken: %q", adminEntry.OnPremisesDistinguishedName)
	}
	if adminEntry.OnPremisesSecurityIdentifier != "S-1-5-21-1" {
		t.Errorf("SID propagation broken: %q", adminEntry.OnPremisesSecurityIdentifier)
	}
}

func TestBuildHybridLinks_MultipleAdminRoles(t *testing.T) {
	tr := boolPtr2(true)
	d := &DetectorData{
		Users: []types.User{
			mkAzureUser("u1", "x@t.com", tr, strPtr("DN=x"), strPtr("SID=x"), strPtr("x"), strPtr("imm")),
		},
		AzureRoleAssignments: []types.RoleAssignment{
			{PrincipalID: "u1", PrincipalType: "User", RoleID: "62e90394-69f5-4237-9190-012177145e10", RoleName: "Global Administrator"},
			{PrincipalID: "u1", PrincipalType: "User", RoleID: "194ae4cb-b126-40b2-bd5b-6091b380977d", RoleName: "Security Administrator"},
		},
	}
	got := BuildHybridLinksSummary(d, false, "test")
	entry := got.SyncedUsers[0]
	if len(entry.AdminRoles) != 2 {
		t.Errorf("AdminRoles len = %d, want 2", len(entry.AdminRoles))
	}
}

func TestBuildHybridLinks_DevicesBreakdown(t *testing.T) {
	d := &DetectorData{
		AzureDevices: []types.AzureDevice{
			mkDevice("d1", "did1", "WS-01", "ServerAd", "Windows"),
			mkDevice("d2", "did2", "WS-02", "ServerAd", "Windows"),
			mkDevice("d3", "did3", "MAC-01", "AzureAd", "macOS"),
			mkDevice("d4", "did4", "PHONE-01", "Workplace", "iOS"),
			mkDevice("d5", "did5", "UNK", "", ""),
		},
	}
	got := BuildHybridLinksSummary(d, false, "test")
	devs := got.Devices
	if devs.TotalDevices != 5 {
		t.Errorf("TotalDevices = %d, want 5", devs.TotalDevices)
	}
	if devs.HybridAzureAdJoined != 2 {
		t.Errorf("HAJ = %d, want 2", devs.HybridAzureAdJoined)
	}
	if devs.AzureAdJoined != 1 {
		t.Errorf("AzureAdJoined = %d, want 1", devs.AzureAdJoined)
	}
	if devs.WorkplaceJoined != 1 {
		t.Errorf("WorkplaceJoined = %d, want 1", devs.WorkplaceJoined)
	}
	if devs.UnknownTrustType != 1 {
		t.Errorf("UnknownTrustType = %d, want 1", devs.UnknownTrustType)
	}
	if len(devs.HajDevices) != 2 {
		t.Errorf("hajDevices len = %d, want 2 (only ServerAd)", len(devs.HajDevices))
	}
}

func TestBuildHybridLinks_DevicesTruncatedFlagPropagated(t *testing.T) {
	d := &DetectorData{
		AzureDevices: []types.AzureDevice{mkDevice("d1", "did1", "X", "ServerAd", "Windows")},
	}
	got := BuildHybridLinksSummary(d, true, "test")
	if !got.Devices.Truncated {
		t.Error("Truncated flag should propagate to summary.Devices")
	}
}

func TestIsHighRiskFederatedTrust_HighRisk(t *testing.T) {
	p := &types.CrossTenantPartnerPolicy{
		TenantID: "ext-tenant",
		InboundTrust: types.CrossTenantInboundTrust{
			IsMfaAccepted: true,
		},
		B2BDirectConnect: types.CrossTenantPolicyChannels{
			Inbound: types.CrossTenantAccessChannel{
				UsersAndGroups: types.CrossTenantAccessTarget{AccessType: "allowed"},
			},
		},
	}
	if !isHighRiskFederatedTrust(p) {
		t.Error("expected high risk: MFA accepted + B2B Direct Connect inbound allowed")
	}
}

func TestIsHighRiskFederatedTrust_LowRisk_NoMFA(t *testing.T) {
	p := &types.CrossTenantPartnerPolicy{
		InboundTrust: types.CrossTenantInboundTrust{IsMfaAccepted: false},
		B2BDirectConnect: types.CrossTenantPolicyChannels{
			Inbound: types.CrossTenantAccessChannel{
				UsersAndGroups: types.CrossTenantAccessTarget{AccessType: "allowed"},
			},
		},
	}
	if isHighRiskFederatedTrust(p) {
		t.Error("expected low risk: MFA not accepted")
	}
}

func TestIsHighRiskFederatedTrust_LowRisk_NoB2BDirect(t *testing.T) {
	p := &types.CrossTenantPartnerPolicy{
		InboundTrust: types.CrossTenantInboundTrust{IsMfaAccepted: true},
		B2BDirectConnect: types.CrossTenantPolicyChannels{
			Inbound: types.CrossTenantAccessChannel{
				UsersAndGroups: types.CrossTenantAccessTarget{AccessType: "blocked"},
			},
		},
	}
	if isHighRiskFederatedTrust(p) {
		t.Error("expected low risk: B2B Direct Connect inbound blocked")
	}
}

func TestIsHighRiskFederatedTrust_NilPartner(t *testing.T) {
	if isHighRiskFederatedTrust(nil) {
		t.Error("nil partner shouldn't be high risk")
	}
}

func TestBuildHybridLinks_FederatedTrustsDerivation(t *testing.T) {
	d := &DetectorData{
		Users: []types.User{
			mkAzureUser("u1", "u@t.com", boolPtr2(true), strPtr("dn"), strPtr("sid"), strPtr("sam"), strPtr("im")),
		},
		AzureCrossTenantAccess: &types.CrossTenantAccessSummary{
			Partners: []types.CrossTenantPartnerPolicy{
				{
					TenantID:     "low-risk",
					DisplayName:  "Low Risk Partner",
					InboundTrust: types.CrossTenantInboundTrust{IsMfaAccepted: false},
				},
				{
					TenantID:     "high-risk",
					DisplayName:  "High Risk Partner",
					InboundTrust: types.CrossTenantInboundTrust{IsMfaAccepted: true},
					B2BDirectConnect: types.CrossTenantPolicyChannels{
						Inbound: types.CrossTenantAccessChannel{
							UsersAndGroups: types.CrossTenantAccessTarget{AccessType: "allowed"},
						},
					},
				},
			},
		},
	}
	got := BuildHybridLinksSummary(d, false, "test")
	if len(got.FederatedTrusts) != 2 {
		t.Fatalf("FederatedTrusts len = %d, want 2", len(got.FederatedTrusts))
	}
	var lowRisk, highRisk *types.HybridFederatedTrust
	for i := range got.FederatedTrusts {
		switch got.FederatedTrusts[i].TenantID {
		case "low-risk":
			lowRisk = &got.FederatedTrusts[i]
		case "high-risk":
			highRisk = &got.FederatedTrusts[i]
		}
	}
	if lowRisk == nil || highRisk == nil {
		t.Fatal("missing partner")
	}
	if lowRisk.IsHighRisk {
		t.Error("low-risk should be IsHighRisk=false")
	}
	if !highRisk.IsHighRisk {
		t.Error("high-risk should be IsHighRisk=true")
	}
}

func TestBuildHybridLinks_CloudOnlyTenant_SyncDisabled(t *testing.T) {
	fa := boolPtr2(false)
	d := &DetectorData{
		Users: []types.User{
			mkAzureUser("u1", "x@t.com", fa, nil, nil, nil, nil),
			mkAzureUser("u2", "y@t.com", fa, nil, nil, nil, nil),
		},
	}
	got := BuildHybridLinksSummary(d, false, "test")
	if got.SyncStats.SyncEnabled {
		t.Error("SyncEnabled should be false on cloud-only tenant")
	}
	if len(got.SyncedUsers) != 0 {
		t.Errorf("SyncedUsers len = %d, want 0", len(got.SyncedUsers))
	}
}

func TestBuildHybridLinks_HajDeviceFieldsPropagated(t *testing.T) {
	now := time.Now()
	enabled := true
	syncOn := true
	d := &DetectorData{
		AzureDevices: []types.AzureDevice{
			{
				ID: "d1", DeviceID: "did-stable", DisplayName: "WS-01",
				TrustType: "ServerAd", OperatingSystem: "Windows",
				OnPremisesSyncEnabled: &syncOn,
				AccountEnabled:        &enabled,
				ApproximateLastSignIn: &now,
			},
		},
	}
	got := BuildHybridLinksSummary(d, false, "test")
	haj := got.Devices.HajDevices[0]
	if haj.DeviceID != "did-stable" || haj.DisplayName != "WS-01" {
		t.Errorf("propagation broken: %+v", haj)
	}
	if haj.OnPremisesSyncEnabled == nil || !*haj.OnPremisesSyncEnabled {
		t.Error("OnPremisesSyncEnabled should propagate")
	}
	if haj.ApproximateLastSignIn == nil {
		t.Error("ApproximateLastSignIn should propagate")
	}
}

func TestBuildUserAdminMap_NonUserPrincipalsExcluded(t *testing.T) {
	roleAssignments := []types.RoleAssignment{
		{PrincipalID: "u1", PrincipalType: "User", RoleID: "62e90394-69f5-4237-9190-012177145e10", RoleName: "Global Administrator"},
		{PrincipalID: "g1", PrincipalType: "Group", RoleID: "62e90394-69f5-4237-9190-012177145e10", RoleName: "Global Administrator"},
		{PrincipalID: "sp1", PrincipalType: "ServicePrincipal", RoleID: "62e90394-69f5-4237-9190-012177145e10", RoleName: "Global Administrator"},
	}
	got := buildUserAdminMap(roleAssignments)
	if len(got) != 1 {
		t.Errorf("len = %d, want 1 (only User principals)", len(got))
	}
	if _, ok := got["u1"]; !ok {
		t.Error("user u1 should be in admin map")
	}
}

func TestBuildUserAdminMap_NonPrivilegedRolesExcluded(t *testing.T) {
	roleAssignments := []types.RoleAssignment{
		{PrincipalID: "u1", PrincipalType: "User", RoleID: "non-privileged-uuid", RoleName: "Reports Reader"},
	}
	got := buildUserAdminMap(roleAssignments)
	if len(got) != 0 {
		t.Errorf("len = %d, want 0 (non-privileged role)", len(got))
	}
}

func TestBuildUserAdminMap_DuplicatesElided(t *testing.T) {
	roleAssignments := []types.RoleAssignment{
		{PrincipalID: "u1", PrincipalType: "User", RoleID: "62e90394-69f5-4237-9190-012177145e10", RoleName: "Global Administrator", DirectoryScopeID: "/"},
		{PrincipalID: "u1", PrincipalType: "User", RoleID: "62e90394-69f5-4237-9190-012177145e10", RoleName: "Global Administrator", DirectoryScopeID: "/admin-unit-1"},
	}
	got := buildUserAdminMap(roleAssignments)
	if len(got["u1"]) != 1 {
		t.Errorf("u1 roles = %d, want 1 (deduplicated)", len(got["u1"]))
	}
}
