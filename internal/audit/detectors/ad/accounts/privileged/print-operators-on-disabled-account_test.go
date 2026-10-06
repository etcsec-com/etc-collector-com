package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestPrintOperatorsOnDisabledAccount_DisabledMemberFlagged is the baseline
// positive: a disabled direct member of the real Print Operators group
// (S-1-5-32-550) must be counted here.
func TestPrintOperatorsOnDisabledAccount_DisabledMemberFlagged(t *testing.T) {
	dn := "CN=Print Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-550"
	u := types.User{SAMAccountName: "disabled-po-member", MemberOf: []string{dn}, Disabled: true}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewPrintOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled real Print Operators membership)", f.Count)
	}
}

// TestPrintOperatorsOnDisabledAccount_ActiveMemberNotFlagged is the
// partition guard from this detector's side: an enabled direct member of
// the real Print Operators group must not be counted here - it belongs to
// PrintOperatorsDetector instead. The opposite side is asserted by
// TestPrintOperators_DisabledMemberNotFlagged.
func TestPrintOperatorsOnDisabledAccount_ActiveMemberNotFlagged(t *testing.T) {
	dn := "CN=Print Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-550"
	u := types.User{SAMAccountName: "po-member", MemberOf: []string{dn}}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewPrintOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (enabled member must not be counted as a disabled Print Operators member)", f.Count)
	}
}

// TestPrintOperatorsOnDisabledAccount_SeverityIsLow locks this detector's
// severity at Low, distinct from the High of the active-member detector.
func TestPrintOperatorsOnDisabledAccount_SeverityIsLow(t *testing.T) {
	dn := "CN=Print Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-550"
	u := types.User{SAMAccountName: "disabled-po-member", MemberOf: []string{dn}, Disabled: true}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewPrintOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityLow {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityLow)
	}
}

// TestPrintOperatorsOnDisabledAccount_ExactGroupSet locks the RID suffix
// this detector matches to -550 alone, all fixtures disabled: a neighbor
// suffix (-549 Server Operators, -551 Backup Operators, confirmed against
// internal/audit/wellknown_sids.go) carried by a disabled member must not be
// flagged.
func TestPrintOperatorsOnDisabledAccount_ExactGroupSet(t *testing.T) {
	cases := []struct {
		name      string
		suffix    string
		wantCount int
	}{
		{"in_set-550", "-550", 1},
		{"out_of_set-549", "-549", 0},
		{"out_of_set-551", "-551", 0},
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
			f := NewPrintOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
			if f.Count != tc.wantCount {
				t.Fatalf("suffix %s: Count = %d, want %d", tc.suffix, f.Count, tc.wantCount)
			}
		})
	}
}

// TestPrintOperatorsOnDisabledAccount_NeighborRIDSuffixNotFlagged locks the
// hyphen in printOperatorsSIDSuffixes ("-550", not "550") from the disabled
// side: a disabled member of a group whose SID ends in the digits 550
// without the leading hyphen (RID 1550) must not be treated as Print
// Operators. Mirrors TestPrintOperators_NeighborRIDSuffixNotFlagged, since
// both detectors share the same suffix variable.
func TestPrintOperatorsOnDisabledAccount_NeighborRIDSuffixNotFlagged(t *testing.T) {
	dn := "CN=Group-1550,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-9999999999-8888888888-7777777777-1550"
	u := types.User{SAMAccountName: "neighbor-rid-member", MemberOf: []string{dn}, Disabled: true}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewPrintOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (RID suffix -1550 is not -550 and must not be flagged)", f.Count)
	}
}

// TestPrintOperatorsOnDisabledAccount_DescriptionTextLocked locks the
// Detect()-side Description text against silent drift. TestCatalogIsStable
// only compares Doc() (docs_gen.go) to the committed markdown catalog, and
// cannot see a divergence between Doc() and Detect(): without a dedicated
// test, the whole suite passes green even if this string is replaced with
// something arbitrary. This is the client-facing text carried in the audit
// report, not the catalog text.
func TestPrintOperatorsOnDisabledAccount_DescriptionTextLocked(t *testing.T) {
	dn := "CN=Print Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-550"
	u := types.User{SAMAccountName: "disabled-po-member", MemberOf: []string{dn}, Disabled: true}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	want := "Disabled users who are direct members of Print Operators cannot authenticate while disabled, so they cannot exercise the privilege. Membership is not removed by this state - it returns to full effect the instant the account is re-enabled. Remediation: remove the account from the group."
	f := NewPrintOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Description != want {
		t.Fatalf("Description = %q, want %q", f.Description, want)
	}
}
