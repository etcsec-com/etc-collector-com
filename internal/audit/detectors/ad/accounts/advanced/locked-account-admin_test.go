package advanced

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestLockedAccountAdmin_UACBitIsDeadOnModernDomains freezes the KB305144
// semantics: since Windows Server 2003, the UAC LOCKOUT bit
// (0x10) no longer reflects live lockout state, so the detector must key
// off lockoutTime instead. Before the fix, isLocked was
// `u.LockedOut || (u.UserAccountControl&0x10) != 0`, but LockedOut is
// itself derived from that same dead bit (parser.go), so the whole
// expression could never fire independently of it.
func TestLockedAccountAdmin_UACBitIsDeadOnModernDomains(t *testing.T) {
	d := NewLockedAccountAdminDetector()

	daDN := "CN=Domain Admins,CN=Users,DC=corp,DC=local"
	daSID := "S-1-5-21-1111111111-2222222222-3333333333-512"
	objectBySID := map[string]*audit.ObjectMeta{daSID: {DN: daDN, SID: daSID, EntityType: types.EntityTypeGroup}}

	baseUser := types.User{
		MemberOf: []string{daDN},
	}

	cases := []struct {
		name      string
		user      types.User
		wantCount int
	}{
		{
			name: "UAC LOCKOUT bit set, no lockoutTime (modern domain false signal)",
			user: func() types.User {
				u := baseUser
				u.UserAccountControl = 0x10
				u.LockedOut = true // as set by parser.go from the same dead bit
				return u
			}(),
			wantCount: 0,
		},
		{
			name: "lockoutTime set, UAC bit clear (real lockout)",
			user: func() types.User {
				u := baseUser
				u.LockoutTime = time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
				return u
			}(),
			wantCount: 1,
		},
		{
			name:      "no lockout signal at all",
			user:      baseUser,
			wantCount: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{Users: []types.User{tc.user}, ObjectBySID: objectBySID}
			findings := d.Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Fatalf("expected count=%d, got %d (UAC-bit dead-code regression?)",
					tc.wantCount, findings[0].Count)
			}
		})
	}
}

// TestLockedAccountAdmin_HomonymGroupNotFlagged is the homonym-group case:
// a group whose CN is literally "Backup Operators" but which carries an
// ordinary domain RID (not -551) grants no real admin membership.
func TestLockedAccountAdmin_HomonymGroupNotFlagged(t *testing.T) {
	fakeDN := "CN=Backup Operators,CN=Users,DC=example,DC=com"
	fakeSID := "S-1-5-21-1111111111-2222222222-3333333333-9107"
	u := types.User{
		LockoutTime: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC),
		MemberOf:    []string{fakeDN},
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{fakeSID: {DN: fakeDN, SID: fakeSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewLockedAccountAdminDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (Backup-Operators-named group with an ordinary RID must not be treated as admin)", f.Count)
	}
}

// TestLockedAccountAdmin_RenamedGroupStillFlagged is the renamed-group
// case: the real Backup Operators group (S-1-5-32-551) renamed to its
// French localized display name must still be recognized by SID suffix.
func TestLockedAccountAdmin_RenamedGroupStillFlagged(t *testing.T) {
	localizedDN := "CN=Opérateurs de sauvegarde,CN=Builtin,DC=example,DC=com"
	realSID := "S-1-5-32-551"
	u := types.User{
		LockoutTime: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC),
		MemberOf:    []string{localizedDN},
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{realSID: {DN: localizedDN, SID: realSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewLockedAccountAdminDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real Backup Operators group under a localized name must still be flagged)", f.Count)
	}
}

// TestLockedAccountAdmin_ExactGroupSet is the table-driven exact-set lock:
// inSet is adminGroupSIDSuffixes' 7 suffixes, written here as a literal
// (never read from the package var) and cross-checked against
// docs/security-validation/results/privileged-by-sid/VERDICT.md §1.
// universe is the union of RID suffixes used by any of the ten detectors
// that share this package's privgroups SID-suffix resolver (28 suffixes),
// plus two witnesses used by NONE of them: -520 (Group Policy Creator
// Owners, a well-known privileged RID this detector must NOT flag) and
// -547 (Power Users), both confirmed against
// internal/audit/wellknown_sids.go.
// Every locked user is a member of exactly one group; every suffix in
// inSet must be flagged, every suffix in universe outside inSet must not.
func TestLockedAccountAdmin_ExactGroupSet(t *testing.T) {
	inSet := []string{"-512", "-519", "-518", "-544", "-548", "-549", "-551"}
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
	lockoutTime := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	for _, suffix := range inSet {
		suffix := suffix
		t.Run("in_set"+suffix, func(t *testing.T) {
			dn := "CN=Group" + suffix + ",CN=Users,DC=example,DC=com"
			sid := "S-1-5-21-9999999999-8888888888-7777777777" + suffix
			u := types.User{LockoutTime: lockoutTime, MemberOf: []string{dn}}
			data := &audit.DetectorData{
				Users:       []types.User{u},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewLockedAccountAdminDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("suffix %s is in adminGroupSIDSuffixes; locked membership must be flagged, got Count=%d, want 1", suffix, f.Count)
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
			u := types.User{LockoutTime: lockoutTime, MemberOf: []string{dn}}
			data := &audit.DetectorData{
				Users:       []types.User{u},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewLockedAccountAdminDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("suffix %s is NOT in adminGroupSIDSuffixes; locked membership must not be flagged, got Count=%d, want 0", suffix, f.Count)
			}
		})
	}
}
