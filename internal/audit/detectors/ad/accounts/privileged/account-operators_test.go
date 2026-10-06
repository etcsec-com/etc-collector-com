package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAccountOperators_RealMembershipStillFlagged is a baseline positive:
// direct membership in the real Account Operators group (S-1-5-32-548).
func TestAccountOperators_RealMembershipStillFlagged(t *testing.T) {
	dn := "CN=Account Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-548"
	u := types.User{SAMAccountName: "ao-member", MemberOf: []string{dn}}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewAccountOperatorsDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real Account Operators membership)", f.Count)
	}
}

// TestAccountOperators_HomonymGroupNotFlagged is the homonym-group case: a
// group whose CN is literally "Account Operators" but which carries an
// ordinary domain RID (not -548) grants no real membership. Before the fix
// (strings.Contains(dn, "CN=Account Operators")), this alone would have
// been flagged.
func TestAccountOperators_HomonymGroupNotFlagged(t *testing.T) {
	fakeDN := "CN=Account Operators,CN=Users,DC=example,DC=com"
	fakeSID := "S-1-5-21-1111111111-2222222222-3333333333-9110"
	u := types.User{SAMAccountName: "homonym-member", MemberOf: []string{fakeDN}}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{fakeSID: {DN: fakeDN, SID: fakeSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewAccountOperatorsDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (Account-Operators-named group with an ordinary RID must not be treated as the real group)", f.Count)
	}
}

// TestAccountOperators_RenamedGroupStillFlagged is the renamed-group
// case: the real Account Operators group renamed to its French localized
// display name must still be recognized by SID suffix.
func TestAccountOperators_RenamedGroupStillFlagged(t *testing.T) {
	localizedDN := "CN=Opérateurs de compte,CN=Builtin,DC=example,DC=com"
	realSID := "S-1-5-32-548"
	u := types.User{SAMAccountName: "localized-member", MemberOf: []string{localizedDN}}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{realSID: {DN: localizedDN, SID: realSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewAccountOperatorsDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real Account Operators group under a localized name must still be flagged)", f.Count)
	}
}

// TestAccountOperators_DisabledMemberNotFlagged is the partition guard: a
// disabled direct member of the real Account Operators group must not be
// counted here - it belongs to AccountOperatorsOnDisabledAccountDetector
// instead. Confirms the partition from this detector's side; the opposite
// side (an enabled member must not land in the disabled-account detector) is
// asserted by TestAccountOperatorsOnDisabledAccount_ActiveMemberNotFlagged.
func TestAccountOperators_DisabledMemberNotFlagged(t *testing.T) {
	dn := "CN=Account Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-548"
	u := types.User{SAMAccountName: "disabled-ao-member", MemberOf: []string{dn}, Disabled: true}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewAccountOperatorsDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (disabled member must not be counted as an active Account Operators member)", f.Count)
	}
}

// TestAccountOperators_SeverityIsHigh locks the active-member finding's
// severity: the split must not silently change it.
func TestAccountOperators_SeverityIsHigh(t *testing.T) {
	dn := "CN=Account Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-548"
	u := types.User{SAMAccountName: "ao-member", MemberOf: []string{dn}}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewAccountOperatorsDetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityHigh {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityHigh)
	}
}

// TestAccountOperators_DescriptionTextLocked locks the Detect()-side
// Description text against silent drift. TestCatalogIsStable only compares
// Doc() (docs_gen.go) to the committed markdown catalog, and cannot see a
// divergence between Doc() and Detect(): without a dedicated test, the whole
// suite passes green even if this string is replaced with something
// arbitrary. This is the client-facing text carried in the audit report, not
// the catalog text.
func TestAccountOperators_DescriptionTextLocked(t *testing.T) {
	dn := "CN=Account Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-548"
	u := types.User{SAMAccountName: "ao-member", MemberOf: []string{dn}}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	want := "Users in Account Operators group. Can create/modify user accounts."
	f := NewAccountOperatorsDetector().Detect(context.Background(), data)[0]
	if f.Description != want {
		t.Fatalf("Description = %q, want %q", f.Description, want)
	}
}

// TestAccountOperators_NeighborRIDSuffixNotFlagged locks the hyphen in
// accountOperatorsSIDSuffixes ("-548", not "548"): a group whose SID ends in
// the digits 548 without the leading hyphen (RID 1548, a plain
// strings.HasSuffix match on "548" would catch it) must not be treated as
// Account Operators.
func TestAccountOperators_NeighborRIDSuffixNotFlagged(t *testing.T) {
	dn := "CN=Group-1548,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-9999999999-8888888888-7777777777-1548"
	u := types.User{SAMAccountName: "neighbor-rid-member", MemberOf: []string{dn}}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewAccountOperatorsDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (RID suffix -1548 is not -548 and must not be flagged)", f.Count)
	}
}

// TestAccountOperators_ExactGroupSet is the table-driven exact-set lock:
// inSet is accountOperatorsSIDSuffixes' single suffix, written here as a
// literal (never read from the package var). universe is the union of RID
// suffixes used by any of the ten detectors that share this codebase's
// privgroups SID-suffix resolver (28 suffixes), plus two witnesses used by
// NONE of them: -520 (Group Policy Creator Owners) and -547 (Power Users),
// both confirmed against
// internal/audit/wellknown_sids.go. Only -548 must be flagged; every other
// well-known privileged RID, including the other nine detectors' own
// suffixes, must not.
func TestAccountOperators_ExactGroupSet(t *testing.T) {
	inSet := []string{"-548"}
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
				Users:       []types.User{u},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewAccountOperatorsDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("suffix %s is accountOperatorsSIDSuffixes' own suffix; membership must be flagged, got Count=%d, want 1", suffix, f.Count)
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
				Users:       []types.User{u},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewAccountOperatorsDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("suffix %s is not -548; membership must not be flagged, got Count=%d, want 0", suffix, f.Count)
			}
		})
	}
}
