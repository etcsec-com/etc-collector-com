package advanced

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestDangerousBuiltinMembership_RealMembershipStillFlagged is a baseline
// positive: direct membership in one of the 15 dangerous built-in groups,
// resolved by its real SID, must be flagged.
func TestDangerousBuiltinMembership_RealMembershipStillFlagged(t *testing.T) {
	dn := "CN=Hyper-V Administrators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-578"
	u := types.User{SAMAccountName: "hv-member", Disabled: false, MemberOf: []string{dn}}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewDangerousBuiltinMembershipDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real Hyper-V Administrators membership)", f.Count)
	}
}

// TestDangerousBuiltinMembership_HomonymGroupNotFlagged is the
// homonym-group case: a group whose CN is literally "Cert Publishers" but which
// carries an ordinary domain RID (not -517) grants no real membership in
// the built-in Cert Publishers group. Before the fix
// (helpers.IsInAnyGroup, name-based), this alone would have been flagged.
func TestDangerousBuiltinMembership_HomonymGroupNotFlagged(t *testing.T) {
	fakeDN := "CN=Cert Publishers,CN=Users,DC=example,DC=com"
	fakeSID := "S-1-5-21-1111111111-2222222222-3333333333-9106" // ordinary domain RID, not -517
	u := types.User{SAMAccountName: "homonym-member", Disabled: false, MemberOf: []string{fakeDN}}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{fakeSID: {DN: fakeDN, SID: fakeSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewDangerousBuiltinMembershipDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (Cert-Publishers-named group with an ordinary RID must not be treated as the real group)", f.Count)
	}
}

// TestDangerousBuiltinMembership_RenamedGroupStillFlagged is the
// renamed-group case: the real Cert Publishers group (RID -517) renamed to its
// French localized display name must still be recognized by SID suffix.
func TestDangerousBuiltinMembership_RenamedGroupStillFlagged(t *testing.T) {
	localizedDN := "CN=Éditeurs de certificats,CN=Users,DC=example,DC=com"
	realSID := "S-1-5-21-1111111111-2222222222-3333333333-517"
	u := types.User{SAMAccountName: "localized-member", Disabled: false, MemberOf: []string{localizedDN}}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{realSID: {DN: localizedDN, SID: realSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewDangerousBuiltinMembershipDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real Cert Publishers group under a localized name must still be flagged)", f.Count)
	}
}

// TestDangerousBuiltinMembership_DisabledExcluded pins existing behavior
// unrelated to this migration: disabled accounts are excluded regardless of
// group membership.
func TestDangerousBuiltinMembership_DisabledExcluded(t *testing.T) {
	dn := "CN=Hyper-V Administrators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-578"
	u := types.User{SAMAccountName: "disabled-hv", Disabled: true, MemberOf: []string{dn}}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewDangerousBuiltinMembershipDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (disabled account must be excluded)", f.Count)
	}
}

// TestDangerousBuiltinMembership_DetailsNamesDeriveFromSingleTable proves
// Details["dangerousGroups"] is derived from the SAME (name, suffix) table
// as detection (dangerousBuiltinGroups), not a second hand-maintained name
// list that could silently drift from it: exactly these 15 names, in this
// order, as a []string. want is written here as a literal, independent of
// dangerousBuiltinGroups, so a change to the table's names or order is
// caught rather than trivially mirrored.
func TestDangerousBuiltinMembership_DetailsNamesDeriveFromSingleTable(t *testing.T) {
	want := []string{
		"Cert Publishers",
		"RAS and IAS Servers",
		"Windows Authorization Access Group",
		"Terminal Server License Servers",
		"Incoming Forest Trust Builders",
		"Performance Log Users",
		"Performance Monitor Users",
		"Distributed COM Users",
		"Remote Desktop Users",
		"Network Configuration Operators",
		"Cryptographic Operators",
		"Event Log Readers",
		"Hyper-V Administrators",
		"Access Control Assistance Operators",
		"Remote Management Users",
	}

	dn := "CN=Hyper-V Administrators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-578"
	u := types.User{SAMAccountName: "hv-member", MemberOf: []string{dn}}
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users:          []types.User{u},
		ObjectBySID:    map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewDangerousBuiltinMembershipDetector().Detect(context.Background(), data)[0]
	got, ok := f.Details["dangerousGroups"].([]string)
	if !ok {
		t.Fatalf("Details[\"dangerousGroups\"] type = %T, want []string", f.Details["dangerousGroups"])
	}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q (name or order diverged from dangerousBuiltinGroups)", i, got[i], want[i])
		}
	}
}

// TestDangerousBuiltinMembership_ExactGroupSet is the table-driven exact-set
// lock: inSet is dangerousBuiltinGroups' 15 suffixes, written here as a
// literal (never read from the package var) and cross-checked against
// docs/security-validation/results/privileged-by-sid/VERDICT.md §1.
// universe is the union of RID suffixes used by any of the ten detectors
// that share this codebase's privgroups SID-suffix resolver (28 suffixes),
// plus two witnesses used by NONE of them: -520 (Group Policy Creator
// Owners) and -547 (Power Users), both confirmed against
// internal/audit/wellknown_sids.go. Every suffix in inSet must be counted;
// every suffix in universe but outside inSet must not be.
func TestDangerousBuiltinMembership_ExactGroupSet(t *testing.T) {
	inSet := []string{
		"-517", "-553", "-560", "-561", "-557", "-559", "-558", "-562",
		"-555", "-556", "-569", "-573", "-578", "-579", "-580",
	}
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
			f := NewDangerousBuiltinMembershipDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("suffix %s is in dangerousBuiltinGroups; membership must be flagged, got Count=%d, want 1", suffix, f.Count)
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
			f := NewDangerousBuiltinMembershipDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("suffix %s is NOT in dangerousBuiltinGroups; membership must not be flagged, got Count=%d, want 0", suffix, f.Count)
			}
		})
	}
}
