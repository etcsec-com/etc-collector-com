package other

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAltSecurityIdentities_RealMembershipStillFlagged is a baseline
// positive: a real Backup Operators member (S-1-5-32-551) with a non-empty
// altSecurityIdentities must be flagged.
func TestAltSecurityIdentities_RealMembershipStillFlagged(t *testing.T) {
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-551"
	u := types.User{
		SAMAccountName:        "bo-member",
		AltSecurityIdentities: []string{"X509:<I>CN=CA<S>CN=bo-member"},
		MemberOf:              []string{dn},
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewAltSecurityIdentitiesDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real Backup Operators member with altSecurityIdentities)", f.Count)
	}
}

// TestAltSecurityIdentities_HomonymGroupNotFlagged is the homonym-group
// case: a group whose CN is literally "Backup Operators" but which carries
// an ordinary domain RID (not -551) grants no real privilege.
func TestAltSecurityIdentities_HomonymGroupNotFlagged(t *testing.T) {
	fakeDN := "CN=Backup Operators,CN=Users,DC=example,DC=com"
	fakeSID := "S-1-5-21-1111111111-2222222222-3333333333-9112"
	u := types.User{
		SAMAccountName:        "homonym-member",
		AltSecurityIdentities: []string{"X509:<I>CN=CA<S>CN=homonym-member"},
		MemberOf:              []string{fakeDN},
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{fakeSID: {DN: fakeDN, SID: fakeSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewAltSecurityIdentitiesDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (Backup-Operators-named group with an ordinary RID must not count as privileged)", f.Count)
	}
}

// TestAltSecurityIdentities_RenamedGroupStillFlagged is the
// renamed-group case: the real Backup Operators group renamed to its French
// localized display name must still be recognized by SID suffix.
func TestAltSecurityIdentities_RenamedGroupStillFlagged(t *testing.T) {
	localizedDN := "CN=Opérateurs de sauvegarde,CN=Builtin,DC=example,DC=com"
	realSID := "S-1-5-32-551"
	u := types.User{
		SAMAccountName:        "localized-member",
		AltSecurityIdentities: []string{"X509:<I>CN=CA<S>CN=localized-member"},
		MemberOf:              []string{localizedDN},
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{realSID: {DN: localizedDN, SID: realSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewAltSecurityIdentitiesDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real Backup Operators group under a localized name must still be flagged)", f.Count)
	}
}

// TestAltSecurityIdentities_ExactGroupSet is the table-driven exact-set
// lock: inSet is altSecAdminGroupSIDSuffixes' 8 suffixes, written here as a
// literal (never read from the package var) and cross-checked against
// docs/security-validation/results/privileged-by-sid/VERDICT.md §1.
// universe is the union of RID suffixes used by any of the ten detectors
// that share this package's privgroups SID-suffix resolver (28 suffixes),
// plus two witnesses used by NONE of them: -520 (Group Policy Creator
// Owners) and -547 (Power Users), both confirmed against
// internal/audit/wellknown_sids.go.
func TestAltSecurityIdentities_ExactGroupSet(t *testing.T) {
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

	for _, suffix := range inSet {
		suffix := suffix
		t.Run("in_set"+suffix, func(t *testing.T) {
			dn := "CN=Group" + suffix + ",CN=Users,DC=example,DC=com"
			sid := "S-1-5-21-9999999999-8888888888-7777777777" + suffix
			u := types.User{
				SAMAccountName:        "member" + suffix,
				AltSecurityIdentities: []string{"X509:<I>CN=CA<S>CN=member" + suffix},
				MemberOf:              []string{dn},
			}
			data := &audit.DetectorData{
				Users:       []types.User{u},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewAltSecurityIdentitiesDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("suffix %s is in altSecAdminGroupSIDSuffixes; membership must be flagged, got Count=%d, want 1", suffix, f.Count)
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
				SAMAccountName:        "member" + suffix,
				AltSecurityIdentities: []string{"X509:<I>CN=CA<S>CN=member" + suffix},
				MemberOf:              []string{dn},
			}
			data := &audit.DetectorData{
				Users:       []types.User{u},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewAltSecurityIdentitiesDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("suffix %s is NOT in altSecAdminGroupSIDSuffixes; membership alone must not be flagged, got Count=%d, want 0", suffix, f.Count)
			}
		})
	}
}

// TestAltSecurityIdentities_EmptyAttributeNotFlagged pins existing
// behavior: no altSecurityIdentities value means no finding, regardless of
// group membership.
func TestAltSecurityIdentities_EmptyAttributeNotFlagged(t *testing.T) {
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-551"
	u := types.User{SAMAccountName: "no-altsec", MemberOf: []string{dn}}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewAltSecurityIdentitiesDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (no altSecurityIdentities value)", f.Count)
	}
}
