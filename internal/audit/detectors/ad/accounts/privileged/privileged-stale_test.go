package privileged

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestPrivilegedAccountStale_RealMembershipStillFlagged is a baseline
// positive: a real Print Operators member (RID -550), stale, gets flagged.
func TestPrivilegedAccountStale_RealMembershipStillFlagged(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	dn := "CN=Print Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-550"
	u := types.User{
		SAMAccountName:     "po-member",
		MemberOf:           []string{dn},
		LastLogonTimestamp: now.AddDate(0, 0, -120),
	}
	data := &audit.DetectorData{
		Now:         now,
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewPrivilegedAccountStaleDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real stale Print Operators member)", f.Count)
	}
}

// TestPrivilegedAccountStale_HomonymGroupNotFlagged is the homonym-group
// case: a group whose CN is literally "Backup Operators" but which carries
// an ordinary domain RID (not -551) grants no real privilege - and
// AdminCount is false, so the group is the only possible signal.
func TestPrivilegedAccountStale_HomonymGroupNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	fakeDN := "CN=Backup Operators,CN=Users,DC=example,DC=com"
	fakeSID := "S-1-5-21-1111111111-2222222222-3333333333-9109"
	u := types.User{
		SAMAccountName:     "homonym-member",
		AdminCount:         false,
		MemberOf:           []string{fakeDN},
		LastLogonTimestamp: now.AddDate(0, 0, -120),
	}
	data := &audit.DetectorData{
		Now:         now,
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{fakeSID: {DN: fakeDN, SID: fakeSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewPrivilegedAccountStaleDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (Backup-Operators-named group with an ordinary RID must not count as privileged)", f.Count)
	}
}

// TestPrivilegedAccountStale_RenamedGroupStillFlagged is the
// renamed-group case: the real Backup Operators group renamed to its French
// localized display name must still be recognized by SID suffix.
func TestPrivilegedAccountStale_RenamedGroupStillFlagged(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	localizedDN := "CN=Opérateurs de sauvegarde,CN=Builtin,DC=example,DC=com"
	realSID := "S-1-5-32-551"
	u := types.User{
		SAMAccountName:     "localized-member",
		AdminCount:         false,
		MemberOf:           []string{localizedDN},
		LastLogonTimestamp: now.AddDate(0, 0, -120),
	}
	data := &audit.DetectorData{
		Now:         now,
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{realSID: {DN: localizedDN, SID: realSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewPrivilegedAccountStaleDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real Backup Operators group under a localized name must still be flagged)", f.Count)
	}
}

// TestPrivilegedAccountStale_ExactGroupSet is the table-driven exact-set
// lock: inSet is adminGroupSIDSuffixes' 8 suffixes, written here as a
// literal (never read from the package var) and cross-checked against
// docs/security-validation/results/privileged-by-sid/VERDICT.md §1.
// universe is the union of RID suffixes used by any of the ten detectors
// that share this package's privgroups SID-suffix resolver (28 suffixes),
// plus two witnesses used by NONE of them: -520 (Group Policy Creator
// Owners) and -547 (Power Users), both confirmed against
// internal/audit/wellknown_sids.go. AdminCount is false throughout so group
// membership is the only possible
// signal, isolating it from TestPrivilegedAccountStale_AdminCountAloneStillFlagged
// above.
func TestPrivilegedAccountStale_ExactGroupSet(t *testing.T) {
	inSet := []string{"-512", "-519", "-518", "-544", "-548", "-549", "-551", "-550"}
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
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)

	for _, suffix := range inSet {
		suffix := suffix
		t.Run("in_set"+suffix, func(t *testing.T) {
			dn := "CN=Group" + suffix + ",CN=Users,DC=example,DC=com"
			sid := "S-1-5-21-9999999999-8888888888-7777777777" + suffix
			u := types.User{
				SAMAccountName:     "member" + suffix,
				AdminCount:         false,
				MemberOf:           []string{dn},
				LastLogonTimestamp: now.AddDate(0, 0, -120),
			}
			data := &audit.DetectorData{
				Now:         now,
				Users:       []types.User{u},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewPrivilegedAccountStaleDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("suffix %s is in adminGroupSIDSuffixes; stale membership must be flagged, got Count=%d, want 1", suffix, f.Count)
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
			u := types.User{
				SAMAccountName:     "member" + suffix,
				AdminCount:         false,
				MemberOf:           []string{dn},
				LastLogonTimestamp: now.AddDate(0, 0, -120),
			}
			data := &audit.DetectorData{
				Now:         now,
				Users:       []types.User{u},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewPrivilegedAccountStaleDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("suffix %s is NOT in adminGroupSIDSuffixes; membership alone must not be flagged, got Count=%d, want 0", suffix, f.Count)
			}
		})
	}
}

// TestPrivilegedAccountStale_AdminCountAloneStillFlagged pins existing
// behavior: u.AdminCount alone (no group resolution needed) still triggers,
// untouched by this migration.
func TestPrivilegedAccountStale_AdminCountAloneStillFlagged(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	u := types.User{
		SAMAccountName:     "admincount-only",
		AdminCount:         true,
		LastLogonTimestamp: now.AddDate(0, 0, -120),
	}
	data := &audit.DetectorData{Now: now, Users: []types.User{u}}

	f := NewPrivilegedAccountStaleDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (AdminCount alone must still trigger)", f.Count)
	}
}
