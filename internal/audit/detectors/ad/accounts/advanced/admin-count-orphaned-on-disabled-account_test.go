package advanced

import (
	"context"
	"strconv"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAdminCountOrphanedOnDisabledAccount_DisabledOrphanFlagged mirrors
// TestAdminCountOrphaned_TrulyOrphanedStillFlagged for the disabled
// population: adminCount=1, only a non-protected group membership, but the
// account is disabled - it belongs here, not in the active detector.
func TestAdminCountOrphanedOnDisabledAccount_DisabledOrphanFlagged(t *testing.T) {
	u := types.User{
		SAMAccountName: "former-admin-disabled",
		AdminCount:     true,
		Disabled:       true,
		MemberOf:       []string{"CN=Marketing,CN=Users,DC=corp,DC=local"},
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewAdminCountOrphanedOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("a disabled account with adminCount=1 and only a non-protected group membership must be flagged, got Count=%d, want 1", f.Count)
	}
}

// TestAdminCountOrphanedOnDisabledAccount_ActiveAccountNeverCounted is the
// mirror negative case: an active account, however orphaned, is never
// counted here - it belongs to ADMIN_COUNT_ORPHANED.
func TestAdminCountOrphanedOnDisabledAccount_ActiveAccountNeverCounted(t *testing.T) {
	u := types.User{
		SAMAccountName: "active-orphan",
		AdminCount:     true,
		Disabled:       false,
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewAdminCountOrphanedOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("an active account must never be counted by ADMIN_COUNT_ORPHANED_ON_DISABLED_ACCOUNT, got Count=%d, want 0", f.Count)
	}
}

// TestAdminCountOrphanedOnDisabledAccount_KrbtgtNeverFlagged and
// TestAdminCountOrphanedOnDisabledAccount_PrimaryGroupProtected confirm the
// two shared exemptions (RID, primary group) apply here exactly as they do
// in the active detector - both detectors call the same package-level
// isProtectedAccountRID / primaryGroupIsProtected.
func TestAdminCountOrphanedOnDisabledAccount_KrbtgtNeverFlagged(t *testing.T) {
	u := types.User{
		SAMAccountName: "krbtgt",
		AdminCount:     true,
		Disabled:       true,
		ObjectSID:      "S-1-5-21-1111111111-2222222222-3333333333-502",
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewAdminCountOrphanedOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("krbtgt (RID -502) must never be flagged, even if somehow collected as disabled, got Count=%d", f.Count)
	}
}

func TestAdminCountOrphanedOnDisabledAccount_PrimaryGroupProtected(t *testing.T) {
	const domainSID = "S-1-5-21-1111111111-2222222222-3333333333"
	const groupDN = "CN=Key Admins,CN=Users,DC=corp,DC=local"
	groupSID := domainSID + "-526"

	u := types.User{
		SAMAccountName: "disabled-key-admin",
		AdminCount:     true,
		Disabled:       true,
		PrimaryGroupID: 526,
	}
	data := &audit.DetectorData{
		Users:      []types.User{u},
		DomainInfo: &types.DomainInfo{DomainSID: domainSID},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewAdminCountOrphanedOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("a protected primary group (Key Admins) must exempt a disabled account too, got Count=%d, want 0", f.Count)
	}
}

func TestAdminCountOrphanedOnDisabledAccount_Severity(t *testing.T) {
	data := &audit.DetectorData{}
	f := NewAdminCountOrphanedOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityLow {
		t.Fatalf("ADMIN_COUNT_ORPHANED_ON_DISABLED_ACCOUNT must be Low, got %v", f.Severity)
	}
}

// TestAdminCountOrphanedOnDisabledAccount_DescriptionLocked is a literal
// lock, typed independently of the source.
func TestAdminCountOrphanedOnDisabledAccount_DescriptionLocked(t *testing.T) {
	const want = "Disabled accounts with adminCount=1 that are not a DIRECT member - via memberOf or primary group - of any group AdminSDHolder/SDProp protects (Microsoft Learn, \"Appendix C: Protected Accounts and Groups in Active Directory\", https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory), and are not krbtgt or the built-in Administrator account (identified by RID, not name). A disabled account cannot authenticate ([MS-KILE], \"Check Account Policy for Every TGT Request\", KDC_ERR_CLIENT_REVOKED), so any residual privilege here is currently dormant - but adminCount is not removed by disabling the account, and it returns to full relevance the instant the account is re-enabled. Limitation: membership reached through a NESTED group is not resolved and can still produce a false positive here."

	data := &audit.DetectorData{}
	f := NewAdminCountOrphanedOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Description != want {
		t.Fatalf("ADMIN_COUNT_ORPHANED_ON_DISABLED_ACCOUNT Description drifted from the locked text.\ngot:  %s\nwant: %s", f.Description, want)
	}
}

// TestAdminCountOrphanedOnDisabledAccount_ProtectedMemberOfExempt is C1: a
// DISABLED account, adminCount=1, direct memberOf of a protected group
// (Domain Admins, RID -512, literal SID/RID distinct from any code
// constant) must not be counted here. Before this test, no case in this
// file exercised the memberOf-protected branch for a disabled account at
// all - every existing exemption test here used the RID (krbtgt) or
// primary-group path, so a break in privgroups.IsMemberOfAny's use on the
// disabled path could silently turn every disabled, SDProp-protected
// account (memberOf a protected group) into a false orphan.
func TestAdminCountOrphanedOnDisabledAccount_ProtectedMemberOfExempt(t *testing.T) {
	groupDN := "CN=Domain Admins,CN=Users,DC=corp,DC=local"
	groupSID := "S-1-5-21-4444444444-5555555555-6666666666-512"
	u := types.User{
		SAMAccountName: "disabled-domain-admin",
		AdminCount:     true,
		Disabled:       true,
		MemberOf:       []string{groupDN},
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewAdminCountOrphanedOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("a disabled account with a protected direct memberOf (Domain Admins) must be exempt, got Count=%d, want 0", f.Count)
	}
}

// TestAdminCountOrphanedOnDisabledAccount_PrimaryGroupIndexedButNotProtectedStillFlagged
// is the disabled half of C2: mirrors
// TestAdminCountOrphaned_PrimaryGroupIndexedButNotProtectedStillFlagged with
// Disabled: true. A primary group present in data.ObjectBySID but not in
// protectedGroupDNs must not exempt a disabled account either.
func TestAdminCountOrphanedOnDisabledAccount_PrimaryGroupIndexedButNotProtectedStillFlagged(t *testing.T) {
	const domainSID = "S-1-5-21-7777777777-8888888888-9999999999"
	const primaryGroupRID = 9310 // ordinary global group, arbitrary RID, not a protected suffix
	groupDN := "CN=Marketing,CN=Users,DC=corp,DC=local"
	groupSID := domainSID + "-" + strconv.Itoa(primaryGroupRID)

	u := types.User{
		SAMAccountName: "disabled-primary-group-indexed-not-protected",
		AdminCount:     true,
		Disabled:       true,
		PrimaryGroupID: primaryGroupRID,
	}
	data := &audit.DetectorData{
		Users:      []types.User{u},
		DomainInfo: &types.DomainInfo{DomainSID: domainSID},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewAdminCountOrphanedOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("a primary group present in the index but not in protectedGroupDNs must not exempt a disabled account either, got Count=%d, want 1", f.Count)
	}
}

// TestAdminCountOrphanedOnDisabledAccount_RecommendationLocked is a literal
// lock on Details["recommendation"], typed independently of the source.
func TestAdminCountOrphanedOnDisabledAccount_RecommendationLocked(t *testing.T) {
	const want = "Verify there is no NESTED protected-group membership (direct membership and primary group are already ruled out) before clearing the adminCount flag. If the account is expected to stay disabled and unused, consider removing it instead of re-enabling it later with a stale adminCount flag."

	u := types.User{
		SAMAccountName: "former-admin-disabled-recommendation-lock",
		AdminCount:     true,
		Disabled:       true,
		MemberOf:       []string{"CN=Marketing,CN=Users,DC=corp,DC=local"},
	}
	data := &audit.DetectorData{Users: []types.User{u}, IncludeDetails: true}

	f := NewAdminCountOrphanedOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	got, _ := f.Details["recommendation"].(string)
	if got != want {
		t.Fatalf("ADMIN_COUNT_ORPHANED_ON_DISABLED_ACCOUNT recommendation drifted from the locked text.\ngot:  %s\nwant: %s", got, want)
	}
}
