package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAccountOperatorsOnDisabledAccount_DisabledMemberFlagged is the
// baseline positive: a disabled direct member of the real Account Operators
// group (S-1-5-32-548) must be counted here.
func TestAccountOperatorsOnDisabledAccount_DisabledMemberFlagged(t *testing.T) {
	dn := "CN=Account Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-548"
	u := types.User{SAMAccountName: "disabled-ao-member", MemberOf: []string{dn}, Disabled: true}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewAccountOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled real Account Operators membership)", f.Count)
	}
}

// TestAccountOperatorsOnDisabledAccount_ActiveMemberNotFlagged is the
// partition guard from this detector's side: an enabled direct member of
// the real Account Operators group must not be counted here - it belongs to
// AccountOperatorsDetector instead. The opposite side is asserted by
// TestAccountOperators_DisabledMemberNotFlagged.
func TestAccountOperatorsOnDisabledAccount_ActiveMemberNotFlagged(t *testing.T) {
	dn := "CN=Account Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-548"
	u := types.User{SAMAccountName: "ao-member", MemberOf: []string{dn}}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewAccountOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (enabled member must not be counted as a disabled Account Operators member)", f.Count)
	}
}

// TestAccountOperatorsOnDisabledAccount_SeverityIsLow locks this detector's
// severity at Low, distinct from the High of the active-member detector.
func TestAccountOperatorsOnDisabledAccount_SeverityIsLow(t *testing.T) {
	dn := "CN=Account Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-548"
	u := types.User{SAMAccountName: "disabled-ao-member", MemberOf: []string{dn}, Disabled: true}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewAccountOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityLow {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityLow)
	}
}

// TestAccountOperatorsOnDisabledAccount_DescriptionTextLocked locks the
// Detect()-side Description text against silent drift. TestCatalogIsStable
// only compares Doc() (docs_gen.go) to the committed markdown catalog, and
// cannot see a divergence between Doc() and Detect(): without a dedicated
// test, the whole suite passes green even if this string is replaced with
// something arbitrary. This is the client-facing text carried in the audit
// report, not the catalog text.
func TestAccountOperatorsOnDisabledAccount_DescriptionTextLocked(t *testing.T) {
	dn := "CN=Account Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-548"
	u := types.User{SAMAccountName: "disabled-ao-member", MemberOf: []string{dn}, Disabled: true}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	want := "Disabled users who are direct members of Account Operators cannot authenticate while disabled, so they cannot exercise the privilege. Membership is not removed by this state - it returns to full effect the instant the account is re-enabled. Remediation: remove the account from the group."
	f := NewAccountOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Description != want {
		t.Fatalf("Description = %q, want %q", f.Description, want)
	}
}

// TestAccountOperatorsOnDisabledAccount_NeighborRIDSuffixNotFlagged locks
// the hyphen in accountOperatorsSIDSuffixes ("-548", not "548") from the
// disabled side: a disabled member of a group whose SID ends in the digits
// 548 without the leading hyphen (RID 1548) must not be treated as Account
// Operators. Mirrors TestAccountOperators_NeighborRIDSuffixNotFlagged, since
// both detectors share the same suffix variable.
func TestAccountOperatorsOnDisabledAccount_NeighborRIDSuffixNotFlagged(t *testing.T) {
	dn := "CN=Group-1548,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-9999999999-8888888888-7777777777-1548"
	u := types.User{SAMAccountName: "neighbor-rid-member", MemberOf: []string{dn}, Disabled: true}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewAccountOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (RID suffix -1548 is not -548 and must not be flagged)", f.Count)
	}
}

// TestAccountOperatorsOnDisabledAccount_ExactGroupSet locks the RID suffix
// this detector matches to -548 alone, all fixtures disabled: a neighbor
// suffix (-547 Power Users, -549 Server Operators, confirmed against
// internal/audit/wellknown_sids.go) carried by a disabled member must not be
// flagged.
func TestAccountOperatorsOnDisabledAccount_ExactGroupSet(t *testing.T) {
	cases := []struct {
		name      string
		suffix    string
		wantCount int
	}{
		{"in_set-548", "-548", 1},
		{"out_of_set-547", "-547", 0},
		{"out_of_set-549", "-549", 0},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dn := "CN=Group" + tc.suffix + ",CN=Users,DC=example,DC=com"
			sid := "S-1-5-21-9999999999-8888888888-7777777777" + tc.suffix
			u := types.User{SAMAccountName: "member" + tc.suffix, MemberOf: []string{dn}, Disabled: true}
			data := &audit.DetectorData{
				Users:       []types.User{u},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewAccountOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
			if f.Count != tc.wantCount {
				t.Fatalf("suffix %s: Count = %d, want %d", tc.suffix, f.Count, tc.wantCount)
			}
		})
	}
}
