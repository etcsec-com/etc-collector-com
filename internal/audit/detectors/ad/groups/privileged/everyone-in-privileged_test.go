package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// fspGroup builds a DetectorData with a single group, its SID resolved
// through ObjectBySID exactly as the engine would (see privgroups/resolve.go
// doc): the detector never trusts group.ObjectSID directly, only the
// DN-keyed lookup DNsBySIDSuffix builds from ObjectBySID.
func fspGroup(groupDN, groupSID string, members []string) *audit.DetectorData {
	return &audit.DetectorData{
		Groups: []types.Group{{DN: groupDN, Member: members}},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}
}

// TestEveryoneInPrivileged_FSPEverywhereInBackupOperatorsCounted is the
// live-lab baseline: the real Everyone FSP as a direct member of Backup
// Operators (S-1-5-32-551), exactly DC01's own shape.
func TestEveryoneInPrivileged_FSPEverywhereInBackupOperatorsCounted(t *testing.T) {
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-32-551", []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

	f := NewEveryoneInPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real Everyone FSP in Backup Operators)", f.Count)
	}
}

// TestEveryoneInPrivileged_LocalizedGroupNameStillCounted proves defect 1 is
// fixed: a group whose sAMAccountName is the French localized name carries
// the real Backup Operators SID and must still be flagged. Before the fix
// (strings.EqualFold(groupName, "Backup Operators")), this group would never
// have been considered privileged at all.
func TestEveryoneInPrivileged_LocalizedGroupNameStillCounted(t *testing.T) {
	dn := "CN=Opérateurs de sauvegarde,CN=Builtin,DC=example,DC=com"
	data := &audit.DetectorData{
		Groups: []types.Group{{DN: dn, SAMAccountName: "Opérateurs de sauvegarde", Member: []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=example,DC=com"}}},
		ObjectBySID: map[string]*audit.ObjectMeta{
			"S-1-5-32-551": {DN: dn, SID: "S-1-5-32-551", EntityType: types.EntityTypeGroup},
		},
	}

	f := NewEveryoneInPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (localized Backup Operators name must not block SID-based recognition)", f.Count)
	}
}

// TestEveryoneInPrivileged_HomonymGroupNotFlagged is the mirror case: a
// group literally named "Backup Operators" but carrying an ordinary domain
// RID (not -551) grants no real membership. Before the fix
// (strings.EqualFold(groupName, "Backup Operators")), this alone would have
// been flagged regardless of the members.
func TestEveryoneInPrivileged_HomonymGroupNotFlagged(t *testing.T) {
	dn := "CN=Backup Operators,CN=Users,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-21-1111111111-2222222222-3333333333-9110", []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

	f := NewEveryoneInPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (Backup-Operators-named group with an ordinary RID must not be treated as the real group)", f.Count)
	}
}

// TestEveryoneInPrivileged_WorldwideOUMemberNotFlagged proves defect 2 is
// fixed: an administrator merely organized under OU=Worldwide is not
// Everyone. Before the fix (Contains(memberLower, "world")), this DN alone
// would have triggered a Critical false positive.
func TestEveryoneInPrivileged_WorldwideOUMemberNotFlagged(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-21-1111111111-2222222222-3333333333-512", []string{"CN=Jane,OU=Worldwide,DC=example,DC=com"})

	f := NewEveryoneInPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (a member DN containing \"world\" is not the Everyone FSP)", f.Count)
	}
}

// TestEveryoneInPrivileged_EveryoneTestUserNotFlagged is the mirror case for
// "everyone": a user merely named "Everyone Test" is not the Everyone FSP.
// Before the fix (Contains(memberLower, "everyone")), this DN alone would
// have triggered a Critical false positive.
func TestEveryoneInPrivileged_EveryoneTestUserNotFlagged(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-21-1111111111-2222222222-3333333333-512", []string{"CN=Everyone Test,CN=Users,DC=example,DC=com"})

	f := NewEveryoneInPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (a member DN containing \"everyone\" is not the Everyone FSP)", f.Count)
	}
}

// TestEveryoneInPrivileged_SIDOutsideFSPContainerNotFlagged proves the
// container requirement: a DN whose CN is literally "S-1-1-0" but which
// lives outside CN=ForeignSecurityPrincipals is not the real Everyone FSP -
// AD never places the Everyone FSP anywhere else, so this can only be a
// same-named decoy object.
func TestEveryoneInPrivileged_SIDOutsideFSPContainerNotFlagged(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-21-1111111111-2222222222-3333333333-512", []string{"CN=S-1-1-0,OU=Staff,DC=example,DC=com"})

	f := NewEveryoneInPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (CN=S-1-1-0 outside the FSP container is not the Everyone FSP)", f.Count)
	}
}

// TestEveryoneInPrivileged_AuthenticatedUsersFSPNotFlagged proves the exact
// SID requirement: the Authenticated Users FSP (S-1-5-11) is a different
// well-known principal and must not be treated as Everyone.
func TestEveryoneInPrivileged_AuthenticatedUsersFSPNotFlagged(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-21-1111111111-2222222222-3333333333-512", []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

	f := NewEveryoneInPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (S-1-5-11 Authenticated Users FSP is not Everyone)", f.Count)
	}
}

// TestEveryoneInPrivileged_OffByOneSIDNotFlagged locks the trailing comma in
// isEveryoneForeignSecurityPrincipal's prefix: "S-1-1-01" (an unrelated SID
// that happens to share "S-1-1-0" as a textual prefix) must not match. A
// bare strings.HasPrefix(lower, "cn=s-1-1-0") without the trailing comma
// would incorrectly accept it.
func TestEveryoneInPrivileged_OffByOneSIDNotFlagged(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-21-1111111111-2222222222-3333333333-512", []string{"CN=S-1-1-01,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

	f := NewEveryoneInPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (S-1-1-01 is not S-1-1-0)", f.Count)
	}
}

// TestEveryoneInPrivileged_EmptyGroupNotFlagged: a privileged group with no
// members at all must not be flagged.
func TestEveryoneInPrivileged_EmptyGroupNotFlagged(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-21-1111111111-2222222222-3333333333-512", nil)

	f := NewEveryoneInPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (a privileged group with no members must not be flagged)", f.Count)
	}
}

// TestEveryoneInPrivileged_TypeIsLocked locks finding.Type against the
// identifier ("GROUP_EVERYONE_IN_PRIVILEGED") silently drifting.
func TestEveryoneInPrivileged_TypeIsLocked(t *testing.T) {
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-32-551", []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

	f := NewEveryoneInPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Type != "GROUP_EVERYONE_IN_PRIVILEGED" {
		t.Fatalf("Type = %q, want %q", f.Type, "GROUP_EVERYONE_IN_PRIVILEGED")
	}
}

// TestEveryoneInPrivileged_SeverityIsCritical locks the finding's severity:
// the fix must not silently downgrade it.
func TestEveryoneInPrivileged_SeverityIsCritical(t *testing.T) {
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-32-551", []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

	f := NewEveryoneInPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityCritical {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityCritical)
	}
}

// TestEveryoneInPrivileged_NestedFSPCNNotFlagged is the L2 lock: a member
// whose DN merely CONTAINS "cn=s-1-1-0,cn=foreignsecurityprincipals," further
// inside the string - not as its own prefix - must not be treated as the
// Everyone FSP. "CN=Child,CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=corp,
// DC=local" reads, RDN by RDN, as an object literally named "Child" living
// INSIDE something that looks like the FSP container's own DN - AD never
// produces this shape (the real FSP container is a single fixed container
// directly under the domain, never nested under an object named after a
// SID), so this can only be a decoy. A bare strings.Contains instead of
// strings.HasPrefix would incorrectly accept it, because the target
// substring does appear, just not at the start of the string.
func TestEveryoneInPrivileged_NestedFSPCNNotFlagged(t *testing.T) {
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-32-551", []string{"CN=Child,CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=corp,DC=local"})

	f := NewEveryoneInPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (the FSP prefix must anchor at the start of the DN, not appear anywhere inside it)", f.Count)
	}
}

// TestEveryoneInPrivileged_AffectedEntitiesWithIncludeDetails is the L9 lock
// (IncludeDetails=true branch): when a privileged group carries the Everyone
// FSP and IncludeDetails is requested, AffectedEntities must contain exactly
// the one matched group's DN.
func TestEveryoneInPrivileged_AffectedEntitiesWithIncludeDetails(t *testing.T) {
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-32-551", []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=example,DC=com"})
	data.IncludeDetails = true

	f := NewEveryoneInPrivilegedDetector().Detect(context.Background(), data)[0]
	if len(f.AffectedEntities) != 1 {
		t.Fatalf("len(AffectedEntities) = %d, want 1", len(f.AffectedEntities))
	}
	if f.AffectedEntities[0].DN != dn {
		t.Fatalf("AffectedEntities[0].DN = %q, want %q", f.AffectedEntities[0].DN, dn)
	}
}

// TestEveryoneInPrivileged_AffectedEntitiesWithoutIncludeDetails is the L9
// lock (IncludeDetails=false branch): the same matching group, but with
// IncludeDetails left at its zero value (false), must produce NO
// AffectedEntities. Before the fix (data.IncludeDetails && len(affected) > 0
// mutated to just len(affected) > 0), entities would leak out regardless of
// the caller's IncludeDetails request.
func TestEveryoneInPrivileged_AffectedEntitiesWithoutIncludeDetails(t *testing.T) {
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-32-551", []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

	f := NewEveryoneInPrivilegedDetector().Detect(context.Background(), data)[0]
	if len(f.AffectedEntities) != 0 {
		t.Fatalf("len(AffectedEntities) = %d, want 0 (IncludeDetails is false)", len(f.AffectedEntities))
	}
}

// TestEveryoneInPrivileged_OverflowRIDNotFlagged is the L10 lock: a
// domain-relative SID ending in "...-1XXX" (an ordinary, much larger RID
// that merely happens to end in the same digits as a real domain-relative
// suffix) must not be treated as that real group. The leading hyphen in
// each suffix literal anchors the match to the RID boundary; dropping it
// (e.g. "-512" mutated to "512") would let such a SID match via
// strings.HasSuffix on the bare digits. Table-driven over all three
// domain-relative suffixes in the list (-512, -518, -519): each subtest
// pins its OWN literal independently, so a dropped hyphen on any one of
// the three is caught by its own subtest rather than relying on the other
// two subtests happening to also fail.
func TestEveryoneInPrivileged_OverflowRIDNotFlagged(t *testing.T) {
	cases := []struct {
		name         string
		collidingRID string
	}{
		{"Domain Admins (-512) vs RID 1512", "1512"},
		{"Schema Admins (-518) vs RID 1518", "1518"},
		{"Enterprise Admins (-519) vs RID 1519", "1519"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
			sid := "S-1-5-21-1111111111-2222222222-3333333333-" + tc.collidingRID
			data := fspGroup(dn, sid, []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

			f := NewEveryoneInPrivilegedDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("Count = %d, want 0 (RID %s must not match a domain-relative suffix missing its leading hyphen)", f.Count, tc.collidingRID)
			}
		})
	}
}

// TestEveryoneInPrivileged_DomainRelativeRIDNotFlagged is the L11 lock: a
// domain-relative SID whose RID exactly matches one of the 5 BUILTIN RIDs
// in the list (S-1-5-21-...-RID, NOT the fixed S-1-5-32-RID) is not the
// real builtin group and must not be flagged. The code requires each full
// "S-1-5-32-RID" literal, not a bare "-RID" suffix, precisely so this
// domain-relative object - distinct from the well-known BUILTIN group of
// the same RID - is excluded. Table-driven over all five BUILTIN suffixes
// (544, 548, 549, 550, 551): each subtest pins its OWN literal
// independently, so dropping the "S-1-5-32-" prefix on any one of the five
// is caught by its own subtest.
func TestEveryoneInPrivileged_DomainRelativeRIDNotFlagged(t *testing.T) {
	cases := []struct {
		name string
		rid  string
	}{
		{"Administrators (S-1-5-32-544)", "544"},
		{"Account Operators (S-1-5-32-548)", "548"},
		{"Server Operators (S-1-5-32-549)", "549"},
		{"Print Operators (S-1-5-32-550)", "550"},
		{"Backup Operators (S-1-5-32-551)", "551"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dn := "CN=SomeGroup,CN=Users,DC=example,DC=com"
			sid := "S-1-5-21-1111111111-2222222222-3333333333-" + tc.rid
			data := fspGroup(dn, sid, []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

			f := NewEveryoneInPrivilegedDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("Count = %d, want 0 (a domain-relative RID of %s is not the builtin S-1-5-32-%s)", f.Count, tc.rid, tc.rid)
			}
		})
	}
}

// TestEveryoneInPrivileged_ExactGroupSet is the table-driven exact-set lock:
// inSet is everyoneInPrivilegedSIDSuffixes written here as literals (never
// read from the package var, per the LAPS-GUID lesson - a fixture built from
// the same constant it compares against cannot fail on drift). universe adds
// two witnesses confirmed absent from the list: -520 (Group Policy Creator
// Owners) and -547 (Power Users), both in wellknown_sids.go. For each of the
// 8 SID suffixes, a dedicated case proves the FSP is flagged when that SID
// is present and NOT when it is removed from the candidate group - i.e. a
// dedicated test rougit when that SID suffix is deleted from the code's
// list (mutations M7..M14).
func TestEveryoneInPrivileged_ExactGroupSet(t *testing.T) {
	inSet := []string{
		"-512", "-518", "-519",
		"S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551",
	}
	notInSet := []string{"-520", "-547", "S-1-5-32-545", "S-1-5-32-546"}

	for _, sid := range inSet {
		sid := sid
		t.Run("in_set_"+sid, func(t *testing.T) {
			dn := "CN=Group" + sid + ",CN=Builtin,DC=example,DC=com"
			data := fspGroup(dn, sid, []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=example,DC=com"})
			f := NewEveryoneInPrivilegedDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("SID %s is in everyoneInPrivilegedSIDSuffixes; Everyone membership must be flagged, got Count=%d, want 1", sid, f.Count)
			}
		})
	}

	for _, sid := range notInSet {
		sid := sid
		t.Run("out_of_set_"+sid, func(t *testing.T) {
			dn := "CN=Group" + sid + ",CN=Builtin,DC=example,DC=com"
			data := fspGroup(dn, sid, []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=example,DC=com"})
			f := NewEveryoneInPrivilegedDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("SID %s is not in everyoneInPrivilegedSIDSuffixes; Everyone membership must not be flagged, got Count=%d, want 0", sid, f.Count)
			}
		})
	}
}
