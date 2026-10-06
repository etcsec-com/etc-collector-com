package other

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestRecentPrivilegedCreation_PrefixedGroupNameNotFlagged pins the
// original fix for the substring-matching bug: a user whose only group is
// "Domain AdminsX" (a distinct, non-privileged group that merely starts
// with the same name, and is not indexed in ObjectBySID at all) must not be
// flagged.
func TestRecentPrivilegedCreation_PrefixedGroupNameNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	d := NewRecentPrivilegedCreationDetector()
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				SAMAccountName: "newhire",
				Created:        now.AddDate(0, 0, -2),
				MemberOf:       []string{"CN=Domain AdminsX,OU=Groups,DC=contoso,DC=com"},
			},
		},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: \"Domain AdminsX\" is not \"Domain Admins\"", findings[0].Count)
	}
}

// TestRecentPrivilegedCreation_ExactGroupNameFlagged pins the positive
// case: an account created 2 days ago and a direct member of the real
// "Domain Admins" group (resolved by SID suffix -512) must still fire.
func TestRecentPrivilegedCreation_ExactGroupNameFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	dn := "CN=Domain Admins,CN=Users,DC=contoso,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	d := NewRecentPrivilegedCreationDetector()
	data := &audit.DetectorData{
		Now:            now,
		IncludeDetails: true,
		Users: []types.User{
			{
				SAMAccountName: "newadmin",
				Created:        now.AddDate(0, 0, -2),
				MemberOf:       []string{dn},
			},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: direct member of the real Domain Admins group", findings[0].Count)
	}
}

// TestRecentPrivilegedCreation_HomonymGroupNotFlagged is the homonym-group
// case: a group whose CN is literally "Backup Operators" but which carries
// an ordinary domain RID (not -551), indexed in ObjectBySID, grants no real
// privilege.
func TestRecentPrivilegedCreation_HomonymGroupNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	fakeDN := "CN=Backup Operators,CN=Users,DC=example,DC=com"
	fakeSID := "S-1-5-21-1111111111-2222222222-3333333333-9113"
	d := NewRecentPrivilegedCreationDetector()
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "homonym-member", Created: now.AddDate(0, 0, -2), MemberOf: []string{fakeDN}},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{fakeSID: {DN: fakeDN, SID: fakeSID, EntityType: types.EntityTypeGroup}},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (Backup-Operators-named group with an ordinary RID must not count as privileged)", findings[0].Count)
	}
}

// TestRecentPrivilegedCreation_RenamedGroupStillFlagged is the
// renamed-group case: the real Backup Operators group renamed to its French
// localized display name must still be recognized by SID suffix.
func TestRecentPrivilegedCreation_RenamedGroupStillFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	localizedDN := "CN=Opérateurs de sauvegarde,CN=Builtin,DC=example,DC=com"
	realSID := "S-1-5-32-551"
	d := NewRecentPrivilegedCreationDetector()
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "localized-member", Created: now.AddDate(0, 0, -2), MemberOf: []string{localizedDN}},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{realSID: {DN: localizedDN, SID: realSID, EntityType: types.EntityTypeGroup}},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (real Backup Operators group under a localized name must still be flagged)", findings[0].Count)
	}
}

// TestRecentPrivilegedCreation_ExactGroupSet is the table-driven exact-set
// lock: inSet is recentPrivilegedCreationSIDSuffixes' 8 suffixes, written
// here as a literal (never read from the package var) and cross-checked
// against docs/security-validation/results/privileged-by-sid/VERDICT.md §1.
// universe is the union of RID suffixes used by any of the ten detectors
// that share this package's privgroups SID-suffix resolver (28 suffixes),
// plus two witnesses used by NONE of them: -520 (Group Policy Creator
// Owners) and -547 (Power Users), both confirmed against
// internal/audit/wellknown_sids.go.
func TestRecentPrivilegedCreation_ExactGroupSet(t *testing.T) {
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
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

	for _, suffix := range inSet {
		suffix := suffix
		t.Run("in_set"+suffix, func(t *testing.T) {
			dn := "CN=Group" + suffix + ",CN=Users,DC=example,DC=com"
			sid := "S-1-5-21-9999999999-8888888888-7777777777" + suffix
			d := NewRecentPrivilegedCreationDetector()
			data := &audit.DetectorData{
				Now: now,
				Users: []types.User{
					{SAMAccountName: "member" + suffix, Created: now.AddDate(0, 0, -2), MemberOf: []string{dn}},
				},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			findings := d.Detect(context.Background(), data)
			if findings[0].Count != 1 {
				t.Fatalf("suffix %s is in recentPrivilegedCreationSIDSuffixes; membership must be flagged, got Count=%d, want 1", suffix, findings[0].Count)
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
			d := NewRecentPrivilegedCreationDetector()
			data := &audit.DetectorData{
				Now: now,
				Users: []types.User{
					{SAMAccountName: "member" + suffix, Created: now.AddDate(0, 0, -2), MemberOf: []string{dn}},
				},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			findings := d.Detect(context.Background(), data)
			if findings[0].Count != 0 {
				t.Fatalf("suffix %s is NOT in recentPrivilegedCreationSIDSuffixes; membership alone must not be flagged, got Count=%d, want 0", suffix, findings[0].Count)
			}
		})
	}
}
