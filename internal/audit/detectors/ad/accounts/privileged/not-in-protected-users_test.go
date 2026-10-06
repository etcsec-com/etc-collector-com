package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// protectedUsersDN/protectedUsersSID are the literal DN/SID fixtures use for
// the REAL Protected Users group (RID -525, verified against Microsoft
// Learn "Security identifiers"). Distinct from any string the detector
// itself hard-codes - the detector never hard-codes a DN or a domain SID.
const (
	protectedUsersDN  = "CN=Protected Users,CN=Users,DC=example,DC=com"
	protectedUsersSID = "S-1-5-21-1111111111-2222222222-3333333333-525"
)

// protectedUsersGroupFixture is the minimal real Protected Users group this
// detector requires to exist - by RID, not by name - before it evaluates
// anything.
func protectedUsersGroupFixture() types.Group {
	return types.Group{CN: "Protected Users", SAMAccountName: "Protected Users", DN: protectedUsersDN, ObjectSID: protectedUsersSID}
}

// withProtectedUsersSID adds the real Protected Users group's ObjectBySID
// entry to a map already containing other groups' entries, and returns it.
func withProtectedUsersSID(m map[string]*audit.ObjectMeta) map[string]*audit.ObjectMeta {
	m[protectedUsersSID] = &audit.ObjectMeta{DN: protectedUsersDN, SID: protectedUsersSID, EntityType: types.EntityTypeGroup}
	return m
}

// TestNotInProtectedUsers_RealMembershipStillFlagged is a baseline positive:
// direct membership in a real privileged group (Backup Operators, S-1-5-32-551),
// not itself in Protected Users, must be flagged.
func TestNotInProtectedUsers_RealMembershipStillFlagged(t *testing.T) {
	boDN := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	boSID := "S-1-5-32-551"
	u := types.User{SAMAccountName: "bo-member", MemberOf: []string{boDN}}
	data := &audit.DetectorData{
		Groups:      []types.Group{protectedUsersGroupFixture()},
		Users:       []types.User{u},
		ObjectBySID: withProtectedUsersSID(map[string]*audit.ObjectMeta{boSID: {DN: boDN, SID: boSID, EntityType: types.EntityTypeGroup}}),
	}

	f := NewNotInProtectedUsersDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real Backup Operators member not in Protected Users)", f.Count)
	}
}

// TestNotInProtectedUsers_HomonymGroupNotFlagged is the homonym-group case:
// a group whose CN is literally "Backup Operators" but which carries an
// ordinary domain RID (not -551) grants no real privilege, so it must not
// make the member "privileged" for this detector's purposes.
func TestNotInProtectedUsers_HomonymGroupNotFlagged(t *testing.T) {
	fakeDN := "CN=Backup Operators,CN=Users,DC=example,DC=com"
	fakeSID := "S-1-5-21-1111111111-2222222222-3333333333-9108"
	u := types.User{SAMAccountName: "homonym-member", MemberOf: []string{fakeDN}}
	data := &audit.DetectorData{
		Groups:      []types.Group{protectedUsersGroupFixture()},
		Users:       []types.User{u},
		ObjectBySID: withProtectedUsersSID(map[string]*audit.ObjectMeta{fakeSID: {DN: fakeDN, SID: fakeSID, EntityType: types.EntityTypeGroup}}),
	}

	f := NewNotInProtectedUsersDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (Backup-Operators-named group with an ordinary RID must not count as privileged)", f.Count)
	}
}

// TestNotInProtectedUsers_RenamedGroupStillFlagged is the renamed-group
// case: the real Backup Operators group renamed to its French localized
// display name must still be recognized by SID suffix.
func TestNotInProtectedUsers_RenamedGroupStillFlagged(t *testing.T) {
	localizedDN := "CN=Opérateurs de sauvegarde,CN=Builtin,DC=example,DC=com"
	realSID := "S-1-5-32-551"
	u := types.User{SAMAccountName: "localized-member", MemberOf: []string{localizedDN}}
	data := &audit.DetectorData{
		Groups:      []types.Group{protectedUsersGroupFixture()},
		Users:       []types.User{u},
		ObjectBySID: withProtectedUsersSID(map[string]*audit.ObjectMeta{realSID: {DN: localizedDN, SID: realSID, EntityType: types.EntityTypeGroup}}),
	}

	f := NewNotInProtectedUsersDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real Backup Operators group under a localized name must still be flagged)", f.Count)
	}
}

// TestNotInProtectedUsers_HomonymProtectedUsersGroupDoesNotProtect: a group
// literally named "Protected Users" but carrying an ordinary domain RID
// (not -525), in a different container, must grant NO protection - a
// privileged member of it must still be flagged, exactly as if that
// membership didn't exist.
func TestNotInProtectedUsers_HomonymProtectedUsersGroupDoesNotProtect(t *testing.T) {
	boDN := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	boSID := "S-1-5-32-551"
	fakeProtectedUsersDN := "CN=Protected Users,CN=Marketing,DC=example,DC=com"
	u := types.User{SAMAccountName: "fake-shielded", MemberOf: []string{boDN, fakeProtectedUsersDN}}
	data := &audit.DetectorData{
		Groups:      []types.Group{protectedUsersGroupFixture()},
		Users:       []types.User{u},
		ObjectBySID: withProtectedUsersSID(map[string]*audit.ObjectMeta{boSID: {DN: boDN, SID: boSID, EntityType: types.EntityTypeGroup}}),
	}

	f := NewNotInProtectedUsersDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (membership in a homonym \"Protected Users\" group with an ordinary RID must not silence this finding)", f.Count)
	}
}

// TestNotInProtectedUsers_RenamedRealProtectedUsersGroupStillProtects is
// the mirror case: the REAL -525 group, renamed to a localized display
// name, must still be recognized as Protected Users via MemberOf (method
// 1) - a group whose name and CN no longer contain "protected users"
// anywhere.
func TestNotInProtectedUsers_RenamedRealProtectedUsersGroupStillProtects(t *testing.T) {
	boDN := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	boSID := "S-1-5-32-551"
	localizedDN := "CN=Utilisateurs protégés,CN=Users,DC=example,DC=com"
	localizedSID := "S-1-5-21-1111111111-2222222222-3333333333-525"
	u := types.User{SAMAccountName: "renamed-shielded", MemberOf: []string{boDN, localizedDN}}
	data := &audit.DetectorData{
		Groups: []types.Group{{CN: "Utilisateurs protégés", SAMAccountName: "Utilisateurs protégés", DN: localizedDN, ObjectSID: localizedSID}},
		Users:  []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			boSID:        {DN: boDN, SID: boSID, EntityType: types.EntityTypeGroup},
			localizedSID: {DN: localizedDN, SID: localizedSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewNotInProtectedUsersDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (the real -525 group under a localized name must still protect its member)", f.Count)
	}
}

// TestNotInProtectedUsers_MemberListAloneProtectsAcrossCase isolates
// method 2 (the real -525 group's own Member list) from method 1: the
// privileged user's own MemberOf never references the Protected Users
// group at all (empty), so only the group's Member list can protect it.
// The group's own DN (as collected in data.Groups) and its Member entry
// each carry a different letter case than the ObjectBySID DN used to
// resolve it by RID and than the User's own DN - a mismatch AD can
// genuinely produce across different attributes/collections. Protection
// must still apply, matched case-insensitively both times.
func TestNotInProtectedUsers_MemberListAloneProtectsAcrossCase(t *testing.T) {
	groupSID := "S-1-5-21-4444444444-5555555555-6666666666-525"
	resolvedDN := "cn=protected users,cn=users,dc=example,dc=com"  // seen via ObjectBySID (RID resolution)
	collectedDN := "CN=PROTECTED USERS,CN=USERS,DC=EXAMPLE,DC=COM" // seen in data.Groups, different case
	memberEntryDN := "CN=CASE-MEMBER,CN=USERS,DC=EXAMPLE,DC=COM"   // as listed in the group's own Member attribute
	userDN := "CN=Case-Member,CN=Users,DC=Example,DC=Com"          // as collected on the User object itself

	u := types.User{SAMAccountName: "case-member", DN: userDN, AdminCount: true}
	data := &audit.DetectorData{
		Groups: []types.Group{{CN: "Protected Users", SAMAccountName: "Protected Users", DN: collectedDN, ObjectSID: groupSID, Member: []string{memberEntryDN}}},
		Users:  []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: resolvedDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewNotInProtectedUsersDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (method 2 alone, across a DN case mismatch on both the group and its member entry, must still protect)", f.Count)
	}
}

// TestNotInProtectedUsers_ProtectedUsersArchiveGroupHasNoEffect covers a
// group whose name is a superstring of "Protected Users" ("Protected Users
// Archive") with an ordinary RID: membership in it must have no bearing on
// this detector, exactly like any other unrelated group.
func TestNotInProtectedUsers_ProtectedUsersArchiveGroupHasNoEffect(t *testing.T) {
	boDN := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	boSID := "S-1-5-32-551"
	archiveDN := "CN=Protected Users Archive,CN=Users,DC=example,DC=com"
	u := types.User{SAMAccountName: "archive-member", MemberOf: []string{boDN, archiveDN}}
	data := &audit.DetectorData{
		Groups:      []types.Group{protectedUsersGroupFixture()},
		Users:       []types.User{u},
		ObjectBySID: withProtectedUsersSID(map[string]*audit.ObjectMeta{boSID: {DN: boDN, SID: boSID, EntityType: types.EntityTypeGroup}}),
	}

	f := NewNotInProtectedUsersDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (\"Protected Users Archive\" is not the real group and must have no effect)", f.Count)
	}
}

// TestNotInProtectedUsers_RenamedAdministratorStillExcludedByRID: the
// built-in Administrator account (RID -500) can be renamed, but must stay
// excluded because the exclusion is keyed on ObjectSID, not on name.
func TestNotInProtectedUsers_RenamedAdministratorStillExcludedByRID(t *testing.T) {
	u := types.User{SAMAccountName: "svc-legacy-root", AdminCount: true, ObjectSID: "S-1-5-21-1111111111-2222222222-3333333333-500"}
	data := &audit.DetectorData{
		Groups:      []types.Group{protectedUsersGroupFixture()},
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{protectedUsersSID: {DN: protectedUsersDN, SID: protectedUsersSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewNotInProtectedUsersDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (RID -500 must stay excluded regardless of SAMAccountName)", f.Count)
	}
}

// TestNotInProtectedUsers_RenamedKrbtgtStillExcludedByRID mirrors the
// Administrator case for krbtgt (RID -502).
func TestNotInProtectedUsers_RenamedKrbtgtStillExcludedByRID(t *testing.T) {
	u := types.User{SAMAccountName: "svc-legacy-kdc", AdminCount: true, ObjectSID: "S-1-5-21-1111111111-2222222222-3333333333-502"}
	data := &audit.DetectorData{
		Groups:      []types.Group{protectedUsersGroupFixture()},
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{protectedUsersSID: {DN: protectedUsersDN, SID: protectedUsersSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewNotInProtectedUsersDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (RID -502 must stay excluded regardless of SAMAccountName)", f.Count)
	}
}

// TestNotInProtectedUsers_NamedAdministratorWithoutRIDNoLongerExcluded is
// the inverse of the RID-500 test: a user merely NAMED "administrator",
// without the -500 RID, is an ordinary privileged account and must no
// longer be excluded by name alone.
func TestNotInProtectedUsers_NamedAdministratorWithoutRIDNoLongerExcluded(t *testing.T) {
	u := types.User{SAMAccountName: "administrator", AdminCount: true, ObjectSID: "S-1-5-21-1111111111-2222222222-3333333333-9301"}
	data := &audit.DetectorData{
		Groups:      []types.Group{protectedUsersGroupFixture()},
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{protectedUsersSID: {DN: protectedUsersDN, SID: protectedUsersSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewNotInProtectedUsersDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (a user merely named \"administrator\" without RID -500 must no longer be excluded by name alone)", f.Count)
	}
}

// TestNotInProtectedUsers_ExactGroupSet is the table-driven exact-set lock:
// inSet is privilegedGroupSIDSuffixes' 7 suffixes, written here as a
// literal (never read from the package var) and cross-checked against
// docs/security-validation/results/privileged-by-sid/VERDICT.md §1.
// universe is the union of RID suffixes used by any of the ten detectors
// that share this package's privgroups SID-suffix resolver (28 suffixes),
// plus two witnesses used by NONE of them: -520 (Group Policy Creator
// Owners) and -547 (Power Users), both confirmed against
// internal/audit/wellknown_sids.go. -500,
// -502 and -525 are exclusions/protection, not privileged-group RIDs, and
// already have their own tests above - they are intentionally absent from
// both inSet and universe here. Each member is otherwise not in Protected
// Users, has no SPN and no -500/-502 ObjectSID, so inSet membership alone
// must flag it and out-of-set membership must not.
func TestNotInProtectedUsers_ExactGroupSet(t *testing.T) {
	inSet := []string{"-512", "-519", "-518", "-544", "-548", "-551", "-549"}
	universe := []string{
		"-512", "-516", "-517", "-518", "-519", "-521", "-526", "-527", "-544",
		"-548", "-549", "-550", "-551", "-552", "-553", "-555", "-556", "-557",
		"-558", "-559", "-560", "-561", "-562", "-569", "-573", "-578", "-579",
		"-580", "-520", "-547",
	}
	inSetIdx := make(map[string]bool, len(inSet))
	for _, s := range inSet {
		inSetIdx[s] = true
	}

	for _, suffix := range inSet {
		suffix := suffix
		t.Run("in_set"+suffix, func(t *testing.T) {
			dn := "CN=Group" + suffix + ",CN=Users,DC=example,DC=com"
			sid := "S-1-5-21-9999999999-8888888888-7777777777" + suffix
			u := types.User{SAMAccountName: "member" + suffix, MemberOf: []string{dn}}
			data := &audit.DetectorData{
				Groups:      []types.Group{protectedUsersGroupFixture()},
				Users:       []types.User{u},
				ObjectBySID: withProtectedUsersSID(map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}}),
			}
			f := NewNotInProtectedUsersDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("suffix %s is in privilegedGroupSIDSuffixes; membership must be flagged (not in Protected Users), got Count=%d, want 1", suffix, f.Count)
			}
		})
	}

	for _, suffix := range universe {
		if inSetIdx[suffix] {
			continue
		}
		suffix := suffix
		t.Run("out_of_set"+suffix, func(t *testing.T) {
			dn := "CN=Group" + suffix + ",CN=Users,DC=example,DC=com"
			sid := "S-1-5-21-9999999999-8888888888-7777777777" + suffix
			u := types.User{SAMAccountName: "member" + suffix, MemberOf: []string{dn}}
			data := &audit.DetectorData{
				Groups:      []types.Group{protectedUsersGroupFixture()},
				Users:       []types.User{u},
				ObjectBySID: withProtectedUsersSID(map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}}),
			}
			f := NewNotInProtectedUsersDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("suffix %s is NOT in privilegedGroupSIDSuffixes; membership alone must not make the user privileged, got Count=%d, want 0", suffix, f.Count)
			}
		})
	}
}

// TestNotInProtectedUsers_NoProtectedUsersGroupStaysSilent locks in the
// declared limitation: on a forest where no group carries the -525 RID
// (absent from the collected index, or a genuinely pre-2012R2 domain), the
// detector stays silent rather than crashing or guessing - same behavior
// as the previous by-name lookup's miss case.
func TestNotInProtectedUsers_NoProtectedUsersGroupStaysSilent(t *testing.T) {
	boDN := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	boSID := "S-1-5-32-551"
	u := types.User{SAMAccountName: "would-be-flagged", MemberOf: []string{boDN}}
	data := &audit.DetectorData{
		Groups:      []types.Group{},
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{boSID: {DN: boDN, SID: boSID, EntityType: types.EntityTypeGroup}},
	}

	findings := NewNotInProtectedUsersDetector().Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0 (no -525 group in the index must produce no finding, not a guess)", len(findings))
	}
}
