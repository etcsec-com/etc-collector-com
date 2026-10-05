package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAuthUsersPrivileged_FSPInServerOperatorsCounted is the live-lab
// baseline: the real Authenticated Users FSP as a direct member of Server
// Operators (S-1-5-32-549), exactly DC01's own shape.
func TestAuthUsersPrivileged_FSPInServerOperatorsCounted(t *testing.T) {
	dn := "CN=Server Operators,CN=Builtin,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-32-549", []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

	f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real Authenticated Users FSP in Server Operators)", f.Count)
	}
}

// TestAuthUsersPrivileged_LocalizedGroupNameStillCounted proves defect 1 is
// fixed: a group whose sAMAccountName is the French localized name carries
// the real Server Operators SID and must still be flagged. Before the fix
// (strings.EqualFold(groupName, "Server Operators")), this group would never
// have been considered privileged at all.
func TestAuthUsersPrivileged_LocalizedGroupNameStillCounted(t *testing.T) {
	dn := "CN=Opérateurs de serveur,CN=Builtin,DC=example,DC=com"
	data := &audit.DetectorData{
		Groups: []types.Group{{DN: dn, SAMAccountName: "Opérateurs de serveur", Member: []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=example,DC=com"}}},
		ObjectBySID: map[string]*audit.ObjectMeta{
			"S-1-5-32-549": {DN: dn, SID: "S-1-5-32-549", EntityType: types.EntityTypeGroup},
		},
	}

	f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (localized Server Operators name must not block SID-based recognition)", f.Count)
	}
}

// TestAuthUsersPrivileged_HomonymGroupNotFlagged is the mirror case: a group
// literally named "Server Operators" but carrying an ordinary domain RID
// (not -549) grants no real membership. Before the fix
// (strings.EqualFold(groupName, "Server Operators")), this alone would have
// been flagged regardless of the members.
func TestAuthUsersPrivileged_HomonymGroupNotFlagged(t *testing.T) {
	dn := "CN=Server Operators,CN=Users,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-21-1111111111-2222222222-3333333333-9110", []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

	f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (Server-Operators-named group with an ordinary RID must not be treated as the real group)", f.Count)
	}
}

// TestAuthUsersPrivileged_AuthenticatedUsersTeamMemberNotFlagged proves
// defect 2 is fixed: a user or group merely NAMED after Authenticated Users
// is not the FSP. Before the fix (Contains(memberLower, "authenticated
// users")), this DN alone would have triggered a High false positive.
func TestAuthUsersPrivileged_AuthenticatedUsersTeamMemberNotFlagged(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-21-1111111111-2222222222-3333333333-512", []string{"CN=Authenticated Users Team,OU=Staff,DC=example,DC=com"})

	f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (a member DN containing \"authenticated users\" is not the Authenticated Users FSP)", f.Count)
	}
}

// TestAuthUsersPrivileged_LocalizedNameSubstringMemberNotFlagged is the
// French-localization mirror of the previous case: before the fix
// (Contains(memberLower, "utilisateurs authentifiés")), a member merely
// named that way would have triggered a false positive.
func TestAuthUsersPrivileged_LocalizedNameSubstringMemberNotFlagged(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-21-1111111111-2222222222-3333333333-512", []string{"CN=Groupe utilisateurs authentifiés,OU=Staff,DC=example,DC=com"})

	f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (a member DN containing \"utilisateurs authentifiés\" is not the Authenticated Users FSP)", f.Count)
	}
}

// TestAuthUsersPrivileged_LocalAccountFSPNotFlagged proves the exact SID
// requirement: the Local account FSP (S-1-5-113) shares "S-1-5-11" as a
// textual prefix but is a different well-known principal. Before the fix
// (Contains(member, "S-1-5-11")), this DN alone would have triggered a
// false positive.
func TestAuthUsersPrivileged_LocalAccountFSPNotFlagged(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-21-1111111111-2222222222-3333333333-512", []string{"CN=S-1-5-113,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

	f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (S-1-5-113 Local account FSP is not Authenticated Users, despite sharing S-1-5-11 as a textual prefix)", f.Count)
	}
}

// TestAuthUsersPrivileged_LocalAccountAdminFSPNotFlagged is the mirror case
// for S-1-5-114 (Local account and member of Administrators group), the
// other well-known SID that shares "S-1-5-11" as a textual prefix.
func TestAuthUsersPrivileged_LocalAccountAdminFSPNotFlagged(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-21-1111111111-2222222222-3333333333-512", []string{"CN=S-1-5-114,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

	f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (S-1-5-114 Local account and member of Administrators group FSP is not Authenticated Users, despite sharing S-1-5-11 as a textual prefix)", f.Count)
	}
}

// TestAuthUsersPrivileged_SIDOutsideFSPContainerNotFlagged proves the
// container requirement: a DN whose CN is literally "S-1-5-11" but which
// lives outside CN=ForeignSecurityPrincipals is not the real Authenticated
// Users FSP - AD never places the Authenticated Users FSP anywhere else, so
// this can only be a same-named decoy object.
func TestAuthUsersPrivileged_SIDOutsideFSPContainerNotFlagged(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-21-1111111111-2222222222-3333333333-512", []string{"CN=S-1-5-11,OU=Staff,DC=example,DC=com"})

	f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (CN=S-1-5-11 outside the FSP container is not the real Authenticated Users FSP)", f.Count)
	}
}

// TestAuthUsersPrivileged_CaseInsensitiveFSPCounted proves the ToLower
// normalization: a differently-cased FSP container name in the member DN
// must still match.
func TestAuthUsersPrivileged_CaseInsensitiveFSPCounted(t *testing.T) {
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-32-551", []string{"CN=S-1-5-11,CN=FOREIGNSECURITYPRINCIPALS,DC=example,DC=com"})

	f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (a differently-cased FSP DN must still match)", f.Count)
	}
}

// TestAuthUsersPrivileged_EveryoneFSPNotFlagged proves the exact SID
// requirement in the other direction: the Everyone FSP (S-1-1-0) is a
// different well-known principal and must not be treated as Authenticated
// Users.
func TestAuthUsersPrivileged_EveryoneFSPNotFlagged(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-21-1111111111-2222222222-3333333333-512", []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

	f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (S-1-1-0 Everyone FSP is not Authenticated Users)", f.Count)
	}
}

// TestAuthUsersPrivileged_NestedFSPCNNotFlagged is the anchor lock: a member
// whose DN merely CONTAINS "cn=s-1-5-11,cn=foreignsecurityprincipals,"
// further inside the string - not as its own prefix - must not be treated
// as the Authenticated Users FSP. AD never produces this shape (the real FSP
// container is a single fixed container directly under the domain, never
// nested under an object named after a SID), so this can only be a decoy. A
// bare strings.Contains instead of strings.HasPrefix would incorrectly
// accept it, because the target substring does appear, just not at the
// start of the string.
func TestAuthUsersPrivileged_NestedFSPCNNotFlagged(t *testing.T) {
	dn := "CN=Server Operators,CN=Builtin,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-32-549", []string{"CN=Child,CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=corp,DC=local"})

	f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (the FSP prefix must anchor at the start of the DN, not appear anywhere inside it)", f.Count)
	}
}

// TestAuthUsersPrivileged_EmptyGroupNotFlagged: a privileged group with no
// members at all must not be flagged.
func TestAuthUsersPrivileged_EmptyGroupNotFlagged(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-21-1111111111-2222222222-3333333333-512", nil)

	f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (a privileged group with no members must not be flagged)", f.Count)
	}
}

// TestAuthUsersPrivileged_TypeIsLocked locks finding.Type against the
// identifier ("GROUP_AUTHENTICATED_USERS_PRIVILEGED") silently drifting.
func TestAuthUsersPrivileged_TypeIsLocked(t *testing.T) {
	dn := "CN=Server Operators,CN=Builtin,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-32-549", []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

	f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Type != "GROUP_AUTHENTICATED_USERS_PRIVILEGED" {
		t.Fatalf("Type = %q, want %q", f.Type, "GROUP_AUTHENTICATED_USERS_PRIVILEGED")
	}
}

// TestAuthUsersPrivileged_SeverityIsHigh locks the finding's severity: the
// fix must not silently change it.
func TestAuthUsersPrivileged_SeverityIsHigh(t *testing.T) {
	dn := "CN=Server Operators,CN=Builtin,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-32-549", []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

	f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityHigh {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityHigh)
	}
}

// TestAuthUsersPrivileged_AffectedEntitiesWithIncludeDetails is the
// IncludeDetails=true branch: when a privileged group carries the
// Authenticated Users FSP and IncludeDetails is requested, AffectedEntities
// must contain exactly the one matched group's DN.
func TestAuthUsersPrivileged_AffectedEntitiesWithIncludeDetails(t *testing.T) {
	dn := "CN=Server Operators,CN=Builtin,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-32-549", []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=example,DC=com"})
	data.IncludeDetails = true

	f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
	if len(f.AffectedEntities) != 1 {
		t.Fatalf("len(AffectedEntities) = %d, want 1", len(f.AffectedEntities))
	}
	if f.AffectedEntities[0].DN != dn {
		t.Fatalf("AffectedEntities[0].DN = %q, want %q", f.AffectedEntities[0].DN, dn)
	}
}

// TestAuthUsersPrivileged_AffectedEntitiesWithoutIncludeDetails is the
// IncludeDetails=false branch: the same matching group, but with
// IncludeDetails left at its zero value (false), must produce NO
// AffectedEntities.
func TestAuthUsersPrivileged_AffectedEntitiesWithoutIncludeDetails(t *testing.T) {
	dn := "CN=Server Operators,CN=Builtin,DC=example,DC=com"
	data := fspGroup(dn, "S-1-5-32-549", []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

	f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
	if len(f.AffectedEntities) != 0 {
		t.Fatalf("len(AffectedEntities) = %d, want 0 (IncludeDetails is false)", len(f.AffectedEntities))
	}
}

// TestAuthUsersPrivileged_OverflowRIDNotFlagged is the domain-relative
// overflow lock: a domain-relative SID ending in "...-1XXX" (an ordinary,
// much larger RID that merely happens to end in the same digits as a real
// domain-relative suffix) must not be treated as that real group. The
// leading hyphen in each suffix literal anchors the match to the RID
// boundary; dropping it (e.g. "-512" mutated to "512") would let such a SID
// match via strings.HasSuffix on the bare digits. Table-driven over all
// three domain-relative suffixes in the list (-512, -518, -519): each
// subtest pins its OWN literal independently.
func TestAuthUsersPrivileged_OverflowRIDNotFlagged(t *testing.T) {
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
			data := fspGroup(dn, sid, []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

			f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("Count = %d, want 0 (RID %s must not match a domain-relative suffix missing its leading hyphen)", f.Count, tc.collidingRID)
			}
		})
	}
}

// TestAuthUsersPrivileged_DomainRelativeRIDNotFlagged is the BUILTIN-prefix
// lock: a domain-relative SID whose RID exactly matches one of the 4
// BUILTIN RIDs in the list (S-1-5-21-...-RID, NOT the fixed S-1-5-32-RID) is
// not the real builtin group and must not be flagged. The code requires
// each full "S-1-5-32-RID" literal, not a bare "-RID" suffix, precisely so
// this domain-relative object - distinct from the well-known BUILTIN group
// of the same RID - is excluded. Table-driven over all four BUILTIN
// suffixes in this list (544, 548, 549, 551 - 550/Print Operators is
// deliberately absent from the list itself, covered by
// TestAuthUsersPrivileged_ExactGroupSet).
func TestAuthUsersPrivileged_DomainRelativeRIDNotFlagged(t *testing.T) {
	cases := []struct {
		name string
		rid  string
	}{
		{"Administrators (S-1-5-32-544)", "544"},
		{"Account Operators (S-1-5-32-548)", "548"},
		{"Server Operators (S-1-5-32-549)", "549"},
		{"Backup Operators (S-1-5-32-551)", "551"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dn := "CN=SomeGroup,CN=Users,DC=example,DC=com"
			sid := "S-1-5-21-1111111111-2222222222-3333333333-" + tc.rid
			data := fspGroup(dn, sid, []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=example,DC=com"})

			f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("Count = %d, want 0 (a domain-relative RID of %s is not the builtin S-1-5-32-%s)", f.Count, tc.rid, tc.rid)
			}
		})
	}
}

// TestAuthUsersPrivileged_ExactGroupSet is the table-driven exact-set lock:
// inSet is authenticatedUsersPrivilegedSIDSuffixes written here as literals
// (never read from the package var, per the LAPS-GUID lesson - a fixture
// built from the same constant it compares against cannot fail on drift).
// notInSet adds witnesses confirmed absent from the list: -520 (Group Policy
// Creator Owners), -547 (Power Users), S-1-5-32-550 (Print Operators - the
// deliberate exclusion this ticket requires), and two adjacent BUILTIN RIDs
// (545, 546). For each of the 7 SID suffixes, a dedicated case proves the
// FSP is flagged when that SID is present and NOT when it is removed from
// the candidate group - i.e. a dedicated test rougit when that SID suffix is
// deleted from the code's list.
func TestAuthUsersPrivileged_ExactGroupSet(t *testing.T) {
	inSet := []string{
		"-512", "-518", "-519",
		"S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-551",
	}
	notInSet := []string{"-520", "-547", "S-1-5-32-550", "S-1-5-32-545", "S-1-5-32-546"}

	for _, sid := range inSet {
		sid := sid
		t.Run("in_set_"+sid, func(t *testing.T) {
			dn := "CN=Group" + sid + ",CN=Builtin,DC=example,DC=com"
			data := fspGroup(dn, sid, []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=example,DC=com"})
			f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("SID %s is in authenticatedUsersPrivilegedSIDSuffixes; Authenticated Users membership must be flagged, got Count=%d, want 1", sid, f.Count)
			}
		})
	}

	for _, sid := range notInSet {
		sid := sid
		t.Run("out_of_set_"+sid, func(t *testing.T) {
			dn := "CN=Group" + sid + ",CN=Builtin,DC=example,DC=com"
			data := fspGroup(dn, sid, []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=example,DC=com"})
			f := NewAuthenticatedUsersPrivilegedDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("SID %s is not in authenticatedUsersPrivilegedSIDSuffixes (Print Operators excluded by product decision); Authenticated Users membership must not be flagged, got Count=%d, want 0", sid, f.Count)
			}
		})
	}
}
