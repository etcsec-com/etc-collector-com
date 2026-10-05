package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestR18GPCO_DoesNotClaimANSSI covers the fact that a full-text audit of
// ANSSI PA-099 found no mention of "Group Policy Creator Owners" anywhere in the
// guide, and the real R18 is about OS security baselines, unrelated. This
// test would have FAILED against the old title/description (claimed
// "ANSSI R18") and passes now that the fabricated attribution is removed.
func TestR18GPCO_DoesNotClaimANSSI(t *testing.T) {
	d := NewR18GPCOMinimalDetector()
	findings := d.Detect(context.Background(), &audit.DetectorData{})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	title, desc := findings[0].Title, findings[0].Description
	if strings.Contains(title, "ANSSI") || strings.Contains(desc, "ANSSI R18 ") {
		t.Errorf("finding must not attribute Group Policy Creator Owners hygiene to ANSSI, got title=%q desc=%q", title, desc)
	}
}

const r18TestDomainSID = "S-1-5-21-4444444444-5555555555-6666666666"

// TestR18GPCO_DirectMemberCounted is a baseline positive: a direct member
// of the real GPCO group (English sAMAccountName, matching RID -520),
// not the built-in Administrator, must be flagged. This already passes on
// main (its EqualFold name match fires on this exact English name); it
// stays green after the fix.
func TestR18GPCO_DirectMemberCounted(t *testing.T) {
	groupSID := r18TestDomainSID + "-520"
	groupDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	memberDN := "CN=extra-member,CN=Users,DC=corp,DC=local"
	memberSID := r18TestDomainSID + "-9001"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DN: groupDN, SAMAccountName: "Group Policy Creator Owners", ObjectSID: groupSID, Members: []string{memberDN}},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
		ObjectByDN: map[string]*audit.ObjectMeta{
			memberDN: {DN: memberDN, SID: memberSID, SAMAccountName: "extra-member", EntityType: types.EntityTypeUser},
		},
	}

	f := NewR18GPCOMinimalDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (direct member of the real GPCO, not built-in Administrator)", f.Count)
	}
}

// TestR18GPCO_BuiltinAdministratorRIDExcluded is a baseline sanity check:
// the built-in Administrator (RID -500, still named "Administrator")
// stays excluded under the RID-based check, same result as main's
// name-based check gives here.
func TestR18GPCO_BuiltinAdministratorRIDExcluded(t *testing.T) {
	groupSID := r18TestDomainSID + "-520"
	groupDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	adminDN := "CN=Administrator,CN=Users,DC=corp,DC=local"
	adminSID := r18TestDomainSID + "-500"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DN: groupDN, SAMAccountName: "Group Policy Creator Owners", ObjectSID: groupSID, Members: []string{adminDN}},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
		ObjectByDN: map[string]*audit.ObjectMeta{
			adminDN: {DN: adminDN, SID: adminSID, SAMAccountName: "Administrator", EntityType: types.EntityTypeUser},
		},
	}

	f := NewR18GPCOMinimalDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (built-in Administrator, RID -500, must stay excluded)", f.Count)
	}
}

// TestR18GPCO_RenamedBuiltinAdministratorExcluded proves the RID fix: the
// built-in Administrator account RENAMED away from "Administrator" keeps
// its RID -500 and must still be excluded. Main's
// EqualFold(entity.SAMAccountName, "Administrator") does not match the new
// name and WRONGLY counts it.
func TestR18GPCO_RenamedBuiltinAdministratorExcluded(t *testing.T) {
	groupSID := r18TestDomainSID + "-520"
	groupDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	renamedDN := "CN=SysAdmin-Renamed,CN=Users,DC=corp,DC=local"
	renamedSID := r18TestDomainSID + "-500"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DN: groupDN, SAMAccountName: "Group Policy Creator Owners", ObjectSID: groupSID, Members: []string{renamedDN}},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
		ObjectByDN: map[string]*audit.ObjectMeta{
			renamedDN: {DN: renamedDN, SID: renamedSID, SAMAccountName: "SysAdmin-Renamed", EntityType: types.EntityTypeUser},
		},
	}

	f := NewR18GPCOMinimalDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (built-in Administrator RENAMED, RID -500 still identifies it - main's name-based exclusion is blind here)", f.Count)
	}
}

// TestR18GPCO_DecoyNamedAdministratorCounted proves the other side of the
// RID fix: an ordinary account merely NAMED "Administrator" but WITHOUT
// RID -500 carries no exemption and must be counted. Main's
// EqualFold(entity.SAMAccountName, "Administrator") WRONGLY excludes it.
func TestR18GPCO_DecoyNamedAdministratorCounted(t *testing.T) {
	groupSID := r18TestDomainSID + "-520"
	groupDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	decoyDN := "CN=Administrator,OU=Decoys,DC=corp,DC=local"
	decoySID := r18TestDomainSID + "-9002"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DN: groupDN, SAMAccountName: "Group Policy Creator Owners", ObjectSID: groupSID, Members: []string{decoyDN}},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
		ObjectByDN: map[string]*audit.ObjectMeta{
			decoyDN: {DN: decoyDN, SID: decoySID, SAMAccountName: "Administrator", EntityType: types.EntityTypeUser},
		},
	}

	f := NewR18GPCOMinimalDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (decoy named \"Administrator\" without RID -500 - main's name-based exclusion false-positives here)", f.Count)
	}
}

// TestR18GPCO_MemberWithNonDashRidSuffixCounted proves the RID match
// requires the leading-dash boundary: a direct member whose ObjectSID ends
// in "...-1500" (RID 1500, an ordinary non-privileged RID that happens to
// contain the digits "500") does NOT match builtinAdministratorRIDSuffix
// ("-500", dash included) and must be COUNTED. Without the dash in the
// suffix constant, a bare "500" would also match this SID's trailing three
// characters and wrongly exclude it.
func TestR18GPCO_MemberWithNonDashRidSuffixCounted(t *testing.T) {
	groupSID := r18TestDomainSID + "-520"
	groupDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	memberDN := "CN=member-1500,CN=Users,DC=corp,DC=local"
	memberSID := r18TestDomainSID + "-1500"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DN: groupDN, SAMAccountName: "Group Policy Creator Owners", ObjectSID: groupSID, Members: []string{memberDN}},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
		ObjectByDN: map[string]*audit.ObjectMeta{
			memberDN: {DN: memberDN, SID: memberSID, SAMAccountName: "member-1500", EntityType: types.EntityTypeUser},
		},
	}

	f := NewR18GPCOMinimalDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (RID -1500 ends in the digits \"500\" but not in the dash-delimited suffix \"-500\" - must not be excluded)", f.Count)
	}
}

// TestR18GPCO_LocalizedGroupRecognized proves the localization fix: on a
// localized forest the GPCO sAMAccountName is not English, so main's
// EqualFold(g.SAMAccountName, "Group Policy Creator Owners") never matches
// - this group, and every member in it, is invisible on main. Matching by
// SID suffix -520 fixes it.
func TestR18GPCO_LocalizedGroupRecognized(t *testing.T) {
	groupSID := r18TestDomainSID + "-520"
	groupDN := "CN=Créateurs propriétaires de la stratégie de groupe,CN=Users,DC=corp,DC=local"
	memberDN := "CN=membre-localise,CN=Users,DC=corp,DC=local"
	memberSID := r18TestDomainSID + "-9003"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DN: groupDN, SAMAccountName: "Créateurs propriétaires de la stratégie de groupe", ObjectSID: groupSID, Members: []string{memberDN}},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
		ObjectByDN: map[string]*audit.ObjectMeta{
			memberDN: {DN: memberDN, SID: memberSID, SAMAccountName: "membre-localise", EntityType: types.EntityTypeUser},
		},
	}

	f := NewR18GPCOMinimalDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (localized GPCO sAMAccountName, real RID -520 - main's English EqualFold match is blind here)", f.Count)
	}
}

// TestR18GPCO_PrimaryGroupCounted proves the primary-group fix: AD never
// writes a memberOf backlink for a user's PRIMARY group, so g.Members never
// carries a user whose primary group is GPCO (PrimaryGroupID 520). Main has
// no primary-group logic at all and misses this user entirely.
func TestR18GPCO_PrimaryGroupCounted(t *testing.T) {
	groupSID := r18TestDomainSID + "-520"
	groupDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	userDN := "CN=primary-group-member,CN=Users,DC=corp,DC=local"
	userSID := r18TestDomainSID + "-9004"
	u := types.User{
		DN:             userDN,
		SAMAccountName: "primary-group-member",
		ObjectSID:      userSID,
		PrimaryGroupID: 520,
	}
	data := &audit.DetectorData{
		Users:      []types.User{u},
		DomainInfo: &types.DomainInfo{DomainSID: r18TestDomainSID},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewR18GPCOMinimalDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (GPCO as PRIMARY group, no memberOf entry - main never checks primary group)", f.Count)
	}
}

// TestR18GPCO_BuiltinAdministratorExcludedViaPrimaryGroup proves the RID
// exclusion is exercised on the PRIMARY-GROUP path too, not just on direct
// membership: the built-in Administrator (ObjectSID suffix -500) whose
// PRIMARY group is GPCO (PrimaryGroupID 520) must stay EXCLUDED. Passing an
// empty or wrong ObjectSID into countExcess on this path would let the
// built-in account through as if it were an ordinary user, since
// isBuiltinAdministratorRID would never see its real RID.
func TestR18GPCO_BuiltinAdministratorExcludedViaPrimaryGroup(t *testing.T) {
	groupSID := r18TestDomainSID + "-520"
	groupDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	adminDN := "CN=Administrator,CN=Users,DC=corp,DC=local"
	adminSID := r18TestDomainSID + "-500"
	u := types.User{
		DN:             adminDN,
		SAMAccountName: "Administrator",
		ObjectSID:      adminSID,
		PrimaryGroupID: 520,
	}
	data := &audit.DetectorData{
		Users:      []types.User{u},
		DomainInfo: &types.DomainInfo{DomainSID: r18TestDomainSID},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewR18GPCOMinimalDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (built-in Administrator, RID -500, with GPCO as PRIMARY group must stay excluded - the RID check must run on this path too)", f.Count)
	}
}

// TestR18GPCO_OrdinaryPrimaryGroupIndexedNotCounted proves the final guard
// in primaryGroupIsGPCO: finding the user's primary group in
// data.ObjectBySID is not enough by itself - that resolved group's DN must
// also be IN the -520 set. ObjectBySID here indexes BOTH the real GPCO
// (-520) and the user's actual primary group, Domain Users (-513, the
// ordinary default), so meta==nil cannot short-circuit before the guard is
// reached - the same mutation-killer shape as the sibling
// primaryGroupIsGpoCreatorOwners check in groups/membership.
func TestR18GPCO_OrdinaryPrimaryGroupIndexedNotCounted(t *testing.T) {
	gpcoSID := r18TestDomainSID + "-520"
	gpcoDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	domainUsersSID := r18TestDomainSID + "-513"
	domainUsersDN := "CN=Domain Users,CN=Users,DC=corp,DC=local"
	userDN := "CN=ordinary-primary-group,CN=Users,DC=corp,DC=local"
	u := types.User{
		DN:             userDN,
		SAMAccountName: "ordinary-primary-group",
		ObjectSID:      r18TestDomainSID + "-9005",
		PrimaryGroupID: 513,
	}
	data := &audit.DetectorData{
		Users:      []types.User{u},
		DomainInfo: &types.DomainInfo{DomainSID: r18TestDomainSID},
		ObjectBySID: map[string]*audit.ObjectMeta{
			gpcoSID:        {DN: gpcoDN, SID: gpcoSID, EntityType: types.EntityTypeGroup},
			domainUsersSID: {DN: domainUsersDN, SID: domainUsersSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewR18GPCOMinimalDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (primary group resolves to Domain Users, indexed but not in the -520 set - must not be counted just because SOME group was found)", f.Count)
	}
}

// TestR18GPCO_PrimaryGroupEmptyDomainSIDNotCounted is the fail-closed guard
// test: with DomainInfo.DomainSID empty, the primary-group SID would be
// built as the bare "-520" (empty prefix + "-" + RID). A spoofed
// ObjectBySID entry under exactly that key must NOT grant membership - the
// guard on empty DomainSID must fire first.
func TestR18GPCO_PrimaryGroupEmptyDomainSIDNotCounted(t *testing.T) {
	spoofedDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	userDN := "CN=empty-domain-sid,CN=Users,DC=corp,DC=local"
	u := types.User{
		DN:             userDN,
		SAMAccountName: "empty-domain-sid",
		ObjectSID:      r18TestDomainSID + "-9006",
		PrimaryGroupID: 520,
	}
	data := &audit.DetectorData{
		Users:      []types.User{u},
		DomainInfo: &types.DomainInfo{DomainSID: ""},
		ObjectBySID: map[string]*audit.ObjectMeta{
			"-520": {DN: spoofedDN, SID: "-520", EntityType: types.EntityTypeGroup},
		},
	}

	f := NewR18GPCOMinimalDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (empty DomainSID must fail closed, not fall through to a spoofed bare \"-520\" key)", f.Count)
	}
}

// TestR18GPCO_MemberAndPrimaryCountedOnce: a user who is both a direct
// g.Members entry AND has GPCO as primary group must be counted exactly
// once, not twice.
func TestR18GPCO_MemberAndPrimaryCountedOnce(t *testing.T) {
	groupSID := r18TestDomainSID + "-520"
	groupDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	userDN := "CN=both-member-and-primary,CN=Users,DC=corp,DC=local"
	userSID := r18TestDomainSID + "-9007"
	u := types.User{
		DN:             userDN,
		SAMAccountName: "both-member-and-primary",
		ObjectSID:      userSID,
		PrimaryGroupID: 520,
	}
	data := &audit.DetectorData{
		Users: []types.User{u},
		Groups: []types.Group{
			{DN: groupDN, SAMAccountName: "Group Policy Creator Owners", ObjectSID: groupSID, Members: []string{userDN}},
		},
		DomainInfo: &types.DomainInfo{DomainSID: r18TestDomainSID},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
		ObjectByDN: map[string]*audit.ObjectMeta{
			userDN: {DN: userDN, SID: userSID, SAMAccountName: "both-member-and-primary", EntityType: types.EntityTypeUser},
		},
	}

	f := NewR18GPCOMinimalDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (direct member AND primary group of the same GPCO must be counted once, not twice)", f.Count)
	}
}

// TestR18GPCO_NoMembersCountZero is the empty baseline.
func TestR18GPCO_NoMembersCountZero(t *testing.T) {
	u := types.User{
		DN:             "CN=unrelated-user,CN=Users,DC=corp,DC=local",
		SAMAccountName: "unrelated-user",
		PrimaryGroupID: 513,
	}
	data := &audit.DetectorData{
		Users:      []types.User{u},
		DomainInfo: &types.DomainInfo{DomainSID: r18TestDomainSID},
	}

	f := NewR18GPCOMinimalDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (no GPCO membership by any path)", f.Count)
	}
}

// TestR18GPCO_EntitiesPresentWithIncludeDetails locks the IncludeDetails
// contract: AffectedEntities is populated when requested, and empty when
// not, for the same underlying excess member.
func TestR18GPCO_EntitiesPresentWithIncludeDetails(t *testing.T) {
	groupSID := r18TestDomainSID + "-520"
	groupDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	memberDN := "CN=details-member,CN=Users,DC=corp,DC=local"
	memberSID := r18TestDomainSID + "-9008"
	baseData := func(includeDetails bool) *audit.DetectorData {
		return &audit.DetectorData{
			IncludeDetails: includeDetails,
			Groups: []types.Group{
				{DN: groupDN, SAMAccountName: "Group Policy Creator Owners", ObjectSID: groupSID, Members: []string{memberDN}},
			},
			ObjectBySID: map[string]*audit.ObjectMeta{
				groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
			},
			ObjectByDN: map[string]*audit.ObjectMeta{
				memberDN: {DN: memberDN, SID: memberSID, SAMAccountName: "details-member", EntityType: types.EntityTypeUser},
			},
		}
	}

	withDetails := NewR18GPCOMinimalDetector().Detect(context.Background(), baseData(true))[0]
	if len(withDetails.AffectedEntities) != 1 || withDetails.AffectedEntities[0].DN != memberDN {
		t.Fatalf("AffectedEntities = %+v, want exactly one entity with DN %q", withDetails.AffectedEntities, memberDN)
	}

	withoutDetails := NewR18GPCOMinimalDetector().Detect(context.Background(), baseData(false))[0]
	if len(withoutDetails.AffectedEntities) != 0 {
		t.Fatalf("AffectedEntities = %+v, want empty when IncludeDetails is false", withoutDetails.AffectedEntities)
	}
	if withoutDetails.Count != 1 {
		t.Fatalf("Count = %d, want 1 (Count is independent of IncludeDetails)", withoutDetails.Count)
	}
}

// TestR18GPCO_TypeAndSeverity locks the finding's identifying fields.
func TestR18GPCO_TypeAndSeverity(t *testing.T) {
	data := &audit.DetectorData{}
	f := NewR18GPCOMinimalDetector().Detect(context.Background(), data)[0]
	if f.Type != "ANSSI_R18_GPCO_NOT_MINIMAL" {
		t.Fatalf("Type = %q, want %q", f.Type, "ANSSI_R18_GPCO_NOT_MINIMAL")
	}
	if f.Severity != types.SeverityMedium {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityMedium)
	}
}
