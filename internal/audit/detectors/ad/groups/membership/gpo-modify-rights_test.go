package membership

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const gpoTestDomainSID = "S-1-5-21-1111111111-2222222222-3333333333"

// TestGpoModifyRights_DirectMemberCounted is a baseline positive: a direct
// member of the real GPCO group (English CN, matching RID -520) must be
// flagged. This already passes on main (its Contains match happens to fire
// on this exact English CN); it stays green after the fix.
func TestGpoModifyRights_DirectMemberCounted(t *testing.T) {
	groupSID := gpoTestDomainSID + "-520"
	groupDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	u := types.User{
		SAMAccountName: "direct-member",
		MemberOf:       []string{groupDN},
	}
	data := &audit.DetectorData{
		Users: []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewGpoModifyRightsDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real GPCO direct member)", f.Count)
	}
}

// TestGpoModifyRights_LocalizedGroupCounted proves the RID-520 fix: on a
// localized forest the GPCO CN is not English, so main's
// strings.Contains(groupDN, "CN=Group Policy Creator Owners") never matches
// - this member is invisible on main. Matching by SID suffix -520 fixes it.
func TestGpoModifyRights_LocalizedGroupCounted(t *testing.T) {
	groupSID := gpoTestDomainSID + "-520"
	groupDN := "CN=Créateurs propriétaires de la stratégie de groupe,CN=Users,DC=corp,DC=local"
	u := types.User{
		SAMAccountName: "localized-member",
		MemberOf:       []string{groupDN},
	}
	data := &audit.DetectorData{
		Users: []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewGpoModifyRightsDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (localized GPCO CN, real RID -520 - main's English substring match is blind here)", f.Count)
	}
}

// TestGpoModifyRights_EnglishHomonymWithoutRID520NotCounted proves the
// homonym fix: a group whose CN merely STARTS WITH the GPCO English text
// but carries a different, non-520 RID is not the real GPCO. Main's
// strings.Contains false-positives on it.
func TestGpoModifyRights_EnglishHomonymWithoutRID520NotCounted(t *testing.T) {
	homonymSID := gpoTestDomainSID + "-3001"
	homonymDN := "CN=Group Policy Creator Owners Backup,CN=Users,DC=corp,DC=local"
	u := types.User{
		SAMAccountName: "homonym-member",
		MemberOf:       []string{homonymDN},
	}
	data := &audit.DetectorData{
		Users: []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			homonymSID: {DN: homonymDN, SID: homonymSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewGpoModifyRightsDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (homonym group's SID does not end in -520 - not the real GPCO, main's substring match false-positives here)", f.Count)
	}
}

// TestGpoModifyRights_PrimaryGroupCounted proves the primary-group fix: AD
// never writes a memberOf backlink for a user's PRIMARY group, so a user
// whose primary group is GPCO (PrimaryGroupID 520) carries no memberOf
// entry for it at all. Main has no primary-group logic and misses this
// user entirely.
func TestGpoModifyRights_PrimaryGroupCounted(t *testing.T) {
	groupSID := gpoTestDomainSID + "-520"
	groupDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	u := types.User{
		SAMAccountName: "primary-group-member",
		PrimaryGroupID: 520,
		MemberOf:       nil,
	}
	data := &audit.DetectorData{
		Users:      []types.User{u},
		DomainInfo: &types.DomainInfo{DomainSID: gpoTestDomainSID},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewGpoModifyRightsDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (GPCO as PRIMARY group, no memberOf entry - main never checks primary group)", f.Count)
	}
}

// TestGpoModifyRights_PrimaryGroupEmptyDomainSIDNotCounted is the fail-closed
// guard test: with DomainInfo.DomainSID empty, the primary-group SID would
// be built as the bare "-520" (empty prefix + "-" + RID). A spoofed
// ObjectBySID entry under exactly that key must NOT grant membership - the
// guard on empty DomainSID must fire first.
func TestGpoModifyRights_PrimaryGroupEmptyDomainSIDNotCounted(t *testing.T) {
	spoofedDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	u := types.User{
		SAMAccountName: "empty-domain-sid-member",
		PrimaryGroupID: 520,
		MemberOf:       nil,
	}
	data := &audit.DetectorData{
		Users:      []types.User{u},
		DomainInfo: &types.DomainInfo{DomainSID: ""},
		ObjectBySID: map[string]*audit.ObjectMeta{
			"-520": {DN: spoofedDN, SID: "-520", EntityType: types.EntityTypeGroup},
		},
	}

	f := NewGpoModifyRightsDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (empty DomainSID must fail closed, not fall through to a spoofed bare \"-520\" key)", f.Count)
	}
}

// TestGpoModifyRights_PrimaryGroupCrossDomainSIDNotCounted proves the
// primary-group lookup is an EXACT match on <DomainSID>-520, not a suffix
// scan: a different domain's real GPCO group (SID ending in -520 too) must
// not satisfy this user's primary-group check just because the RID matches.
func TestGpoModifyRights_PrimaryGroupCrossDomainSIDNotCounted(t *testing.T) {
	const otherDomainSID = "S-1-5-21-9999999999-8888888888-7777777777"
	otherDomainGroupSID := otherDomainSID + "-520"
	otherDomainGroupDN := "CN=Group Policy Creator Owners,CN=Users,DC=contoso,DC=com"
	u := types.User{
		SAMAccountName: "cross-domain-member",
		PrimaryGroupID: 520,
		MemberOf:       nil,
	}
	data := &audit.DetectorData{
		Users:      []types.User{u},
		DomainInfo: &types.DomainInfo{DomainSID: gpoTestDomainSID},
		ObjectBySID: map[string]*audit.ObjectMeta{
			otherDomainGroupSID: {DN: otherDomainGroupDN, SID: otherDomainGroupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewGpoModifyRightsDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (user's domain SID + \"-520\" has no exact ObjectBySID entry; a different domain's -520 group must not match by RID suffix alone)", f.Count)
	}
}

// TestGpoModifyRights_OrdinaryPrimaryGroupIndexedNotCounted proves the final
// guard in primaryGroupIsGpoCreatorOwners: finding the user's primary group
// in data.ObjectBySID is not enough by itself - that resolved group's DN
// must also be IN the -520 set. Here ObjectBySID indexes BOTH the real GPCO
// (-520) and the user's actual primary group, Domain Users (-513, the
// ordinary default) - unlike TestGpoModifyRights_NoMembersCountZero, whose
// empty ObjectBySID lets meta==nil short-circuit before this guard is ever
// reached. On a real domain nearly every user's primary group is 513, so a
// dropped guard here would flag most of the domain.
func TestGpoModifyRights_OrdinaryPrimaryGroupIndexedNotCounted(t *testing.T) {
	gpcoSID := gpoTestDomainSID + "-520"
	gpcoDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	domainUsersSID := gpoTestDomainSID + "-513"
	domainUsersDN := "CN=Domain Users,CN=Users,DC=corp,DC=local"
	u := types.User{
		SAMAccountName: "ordinary-primary-group-indexed",
		PrimaryGroupID: 513,
		MemberOf:       nil,
	}
	data := &audit.DetectorData{
		Users:      []types.User{u},
		DomainInfo: &types.DomainInfo{DomainSID: gpoTestDomainSID},
		ObjectBySID: map[string]*audit.ObjectMeta{
			gpcoSID:        {DN: gpcoDN, SID: gpcoSID, EntityType: types.EntityTypeGroup},
			domainUsersSID: {DN: domainUsersDN, SID: domainUsersSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewGpoModifyRightsDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (primary group resolves to Domain Users, indexed but not in the -520 set - must not be counted just because SOME group was found)", f.Count)
	}
}

// TestGpoModifyRights_SIDSuffixCollisionNotCounted is a boundary/regression
// check on the shared privgroups.DNsBySIDSuffix mechanism as consumed here:
// a group whose SID ends in "-1520" does not end in "-520" (plain string
// suffix, no digit-boundary ambiguity) and must not be counted. The group's
// CN also carries no GPCO text, so this is orthogonal to the naming defect.
func TestGpoModifyRights_SIDSuffixCollisionNotCounted(t *testing.T) {
	decoySID := gpoTestDomainSID + "-1520"
	decoyDN := "CN=Some Other Privileged Group,CN=Users,DC=corp,DC=local"
	u := types.User{
		SAMAccountName: "suffix-collision-member",
		MemberOf:       []string{decoyDN},
	}
	data := &audit.DetectorData{
		Users: []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			decoySID: {DN: decoyDN, SID: decoySID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewGpoModifyRightsDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (SID suffix \"-1520\" is not \"-520\")", f.Count)
	}
}

// TestGpoModifyRights_MemberAndPrimaryCountedOnce: a user who is both a
// direct memberOf entry AND has GPCO as primary group must be counted
// exactly once, not twice.
func TestGpoModifyRights_MemberAndPrimaryCountedOnce(t *testing.T) {
	groupSID := gpoTestDomainSID + "-520"
	groupDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	u := types.User{
		SAMAccountName: "both-member-and-primary",
		PrimaryGroupID: 520,
		MemberOf:       []string{groupDN},
	}
	data := &audit.DetectorData{
		Users:      []types.User{u},
		DomainInfo: &types.DomainInfo{DomainSID: gpoTestDomainSID},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewGpoModifyRightsDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (direct member AND primary group of the same GPCO must be counted once, not twice)", f.Count)
	}
}

// TestGpoModifyRights_NoMembersCountZero is the empty baseline.
func TestGpoModifyRights_NoMembersCountZero(t *testing.T) {
	u := types.User{
		SAMAccountName: "unrelated-user",
		PrimaryGroupID: 513,
		MemberOf:       []string{"CN=Marketing,CN=Users,DC=corp,DC=local"},
	}
	data := &audit.DetectorData{
		Users:      []types.User{u},
		DomainInfo: &types.DomainInfo{DomainSID: gpoTestDomainSID},
	}

	f := NewGpoModifyRightsDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (no GPCO membership by any path)", f.Count)
	}
}

// TestGpoModifyRights_TypeAndSeverity locks the finding's identifying
// fields, absent from any preexisting test on this detector.
func TestGpoModifyRights_TypeAndSeverity(t *testing.T) {
	data := &audit.DetectorData{}
	f := NewGpoModifyRightsDetector().Detect(context.Background(), data)[0]
	if f.Type != "GPO_MODIFY_RIGHTS" {
		t.Fatalf("Type = %q, want %q", f.Type, "GPO_MODIFY_RIGHTS")
	}
	if f.Severity != types.SeverityHigh {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityHigh)
	}
}
