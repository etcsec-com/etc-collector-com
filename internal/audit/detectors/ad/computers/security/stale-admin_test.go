package security

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestComputerStaleWithAdminGroups_RealMembershipStillFlagged is a baseline
// positive: a stale, enabled computer directly in the real Backup
// Operators group (S-1-5-32-551) must be flagged.
func TestComputerStaleWithAdminGroups_RealMembershipStillFlagged(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-551"
	c := types.Computer{
		SAMAccountName:     "STALE-PC$",
		MemberOf:           []string{dn},
		LastLogonTimestamp: now.AddDate(0, 0, -120),
	}
	data := &audit.DetectorData{
		Now:         now,
		Computers:   []types.Computer{c},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewComputerStaleWithAdminGroupsDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real stale Backup Operators computer member)", f.Count)
	}
}

// TestComputerStaleWithAdminGroups_HomonymGroupNotFlagged is the
// homonym-group case: a group whose CN is literally "Backup Operators" but which
// carries an ordinary domain RID (not -551) grants no real privilege.
func TestComputerStaleWithAdminGroups_HomonymGroupNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	fakeDN := "CN=Backup Operators,CN=Users,DC=example,DC=com"
	fakeSID := "S-1-5-21-1111111111-2222222222-3333333333-9114"
	c := types.Computer{
		SAMAccountName:     "HOMONYM-PC$",
		MemberOf:           []string{fakeDN},
		LastLogonTimestamp: now.AddDate(0, 0, -120),
	}
	data := &audit.DetectorData{
		Now:         now,
		Computers:   []types.Computer{c},
		ObjectBySID: map[string]*audit.ObjectMeta{fakeSID: {DN: fakeDN, SID: fakeSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewComputerStaleWithAdminGroupsDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (Backup-Operators-named group with an ordinary RID must not count as admin)", f.Count)
	}
}

// TestComputerStaleWithAdminGroups_RenamedGroupStillFlagged is the
// renamed-group case: the real Backup Operators group renamed to its French
// localized display name must still be recognized by SID suffix.
func TestComputerStaleWithAdminGroups_RenamedGroupStillFlagged(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	localizedDN := "CN=Opérateurs de sauvegarde,CN=Builtin,DC=example,DC=com"
	realSID := "S-1-5-32-551"
	c := types.Computer{
		SAMAccountName:     "LOCALIZED-PC$",
		MemberOf:           []string{localizedDN},
		LastLogonTimestamp: now.AddDate(0, 0, -120),
	}
	data := &audit.DetectorData{
		Now:         now,
		Computers:   []types.Computer{c},
		ObjectBySID: map[string]*audit.ObjectMeta{realSID: {DN: localizedDN, SID: realSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewComputerStaleWithAdminGroupsDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real Backup Operators group under a localized name must still be flagged)", f.Count)
	}
}

// TestComputerStaleWithAdminGroups_ExactGroupSet is the table-driven
// exact-set lock: inSet is staleAdminGroupSIDSuffixes' 8 suffixes, written
// here as a literal (never read from the package var) and cross-checked
// against docs/security-validation/results/privileged-by-sid/VERDICT.md §1.
// universe is the union of RID suffixes used by any of the ten detectors
// that share this package's privgroups SID-suffix resolver (28 suffixes),
// plus two witnesses used by NONE of them: -520 (Group Policy Creator
// Owners) and -547 (Power Users), both confirmed against
// internal/audit/wellknown_sids.go.
func TestComputerStaleWithAdminGroups_ExactGroupSet(t *testing.T) {
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
			c := types.Computer{
				SAMAccountName:     "PC" + suffix + "$",
				MemberOf:           []string{dn},
				LastLogonTimestamp: now.AddDate(0, 0, -120),
			}
			data := &audit.DetectorData{
				Now:         now,
				Computers:   []types.Computer{c},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewComputerStaleWithAdminGroupsDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("suffix %s is in staleAdminGroupSIDSuffixes; stale computer membership must be flagged, got Count=%d, want 1", suffix, f.Count)
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
			c := types.Computer{
				SAMAccountName:     "PC" + suffix + "$",
				MemberOf:           []string{dn},
				LastLogonTimestamp: now.AddDate(0, 0, -120),
			}
			data := &audit.DetectorData{
				Now:         now,
				Computers:   []types.Computer{c},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewComputerStaleWithAdminGroupsDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("suffix %s is NOT in staleAdminGroupSIDSuffixes; membership alone must not be flagged, got Count=%d, want 0", suffix, f.Count)
			}
		})
	}
}

// TestComputerStaleWithAdminGroups_NotStaleNotFlagged pins existing
// behavior: a recent logon must not be flagged even with real admin
// membership.
func TestComputerStaleWithAdminGroups_NotStaleNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-551"
	c := types.Computer{
		SAMAccountName:     "RECENT-PC$",
		MemberOf:           []string{dn},
		LastLogonTimestamp: now.AddDate(0, 0, -10),
	}
	data := &audit.DetectorData{
		Now:         now,
		Computers:   []types.Computer{c},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewComputerStaleWithAdminGroupsDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (recent logon must not be flagged)", f.Count)
	}
}
