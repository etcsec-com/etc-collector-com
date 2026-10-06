package membership

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestDnsAdminsMember_RealGroupMemberFlagged is the baseline positive: a
// direct member of the real DnsAdmins group (resolved by sAMAccountName,
// present in data.Groups) must be flagged.
func TestDnsAdminsMember_RealGroupMemberFlagged(t *testing.T) {
	g := types.Group{
		SAMAccountName: "DnsAdmins",
		DN:             "CN=DnsAdmins,CN=Users,DC=example,DC=com",
	}
	u := types.User{
		SAMAccountName: "dns-member",
		MemberOf:       []string{"CN=DnsAdmins,CN=Users,DC=example,DC=com"},
	}
	data := &audit.DetectorData{Users: []types.User{u}, Groups: []types.Group{g}}

	f := NewDnsAdminsMemberDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real DnsAdmins membership, resolved by sAMAccountName)", f.Count)
	}
}

// TestDnsAdminsMember_HomonymGroupNotFlagged is the false-positive case: a
// group whose CN is the EXACT literal "DnsAdmins" but whose sAMAccountName
// is something else entirely (a different group, in a different OU, with a
// different SID) must NOT be flagged. This is the case the old CN-based
// code got wrong.
func TestDnsAdminsMember_HomonymGroupNotFlagged(t *testing.T) {
	g := types.Group{
		SAMAccountName: "t377-dns-homonyme",
		DN:             "CN=DnsAdmins,OU=T377-Dns,DC=example,DC=com",
	}
	u := types.User{
		SAMAccountName: "homonym-member",
		MemberOf:       []string{"CN=DnsAdmins,OU=T377-Dns,DC=example,DC=com"},
	}
	data := &audit.DetectorData{Users: []types.User{u}, Groups: []types.Group{g}}

	f := NewDnsAdminsMemberDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (CN homonym with a different sAMAccountName is not the real DnsAdmins)", f.Count)
	}
}

// TestDnsAdminsMember_SAMAccountNameSuperstringNotFlagged is a second
// negative: a group whose sAMAccountName merely STARTS WITH "DnsAdmins"
// (e.g. "DnsAdminsExtra") is a different group entirely and must not match
// strings.EqualFold("DnsAdminsExtra", "DnsAdmins").
func TestDnsAdminsMember_SAMAccountNameSuperstringNotFlagged(t *testing.T) {
	g := types.Group{
		SAMAccountName: "DnsAdminsExtra",
		DN:             "CN=DnsAdminsExtra,CN=Users,DC=example,DC=com",
	}
	u := types.User{
		SAMAccountName: "superstring-member",
		MemberOf:       []string{"CN=DnsAdminsExtra,CN=Users,DC=example,DC=com"},
	}
	data := &audit.DetectorData{Users: []types.User{u}, Groups: []types.Group{g}}

	f := NewDnsAdminsMemberDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (\"DnsAdminsExtra\" is not \"DnsAdmins\")", f.Count)
	}
}

// TestDnsAdminsMember_RenamedGroupNotDetected documents the declared
// limitation: DnsAdmins has no fixed RID, so this detector resolves it by
// sAMAccountName; a real DnsAdmins group renamed on a non-English or
// customized forest carries a different sAMAccountName too, and is NOT
// recognized. This is the accepted, documented behavior - not a bug - and
// the test pins it so a future change is a deliberate decision, not an
// accident.
func TestDnsAdminsMember_RenamedGroupNotDetected(t *testing.T) {
	g := types.Group{
		SAMAccountName: "Administrateurs DNS",
		DN:             "CN=Administrateurs DNS,CN=Users,DC=example,DC=com",
	}
	u := types.User{
		SAMAccountName: "renamed-dnsadmins-member",
		MemberOf:       []string{"CN=Administrateurs DNS,CN=Users,DC=example,DC=com"},
	}
	data := &audit.DetectorData{Users: []types.User{u}, Groups: []types.Group{g}}

	f := NewDnsAdminsMemberDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (documented limitation: a renamed DnsAdmins group carries a different sAMAccountName and is not recognized)", f.Count)
	}
}

// TestDnsAdminsMember_GroupNotCollectedFailsClosed is the required fail-
// closed case: no group with sAMAccountName "DnsAdmins" was collected at
// all (data.Groups is empty), even though a user's memberOf contains a DN
// that WOULD have matched the old CN-based code. The new code must count
// nobody, since there is nothing to resolve against - under-detection, not
// a false positive.
//
// Mutation testee (M5), sur le detecteur : dans isMemberOfDnsAdmins, ajouter un repli sur
// l'ancien test du premier composant du DN (strings.HasPrefix(strings.
// ToLower(dn), "cn=dnsadmins")) quand dnsAdminsDNs est vide, pour simuler
// la reintroduction du defaut corrige par ce ticket. Mesure reelle (go test
// -v) : QUATRE tests rougissent, pas seulement celui-ci - HomonymGroupNot
// Flagged, SAMAccountNameSuperstringNotFlagged et SAMAccountNameNotCNMatched
// rougissent aussi, car leurs sAMAccountName ne matchent jamais "DnsAdmins"
// (dnsAdminsDNs vide dans les quatre cas) ET leurs memberOf commencent tous
// par le premier RDN "cn=dnsadmins" (CN exact ou prefixe "DnsAdminsExtra").
// Seul RenamedGroupNotDetected reste vert, son memberOf ("Administrateurs
// DNS") ne commençant pas par ce prefixe. Repli retire ensuite, verifie par
// grep - restauration confirmee par les 12 tests de nouveau verts.
func TestDnsAdminsMember_GroupNotCollectedFailsClosed(t *testing.T) {
	u := types.User{
		SAMAccountName: "orphan-member",
		MemberOf:       []string{"CN=DnsAdmins,CN=Users,DC=example,DC=com"},
	}
	data := &audit.DetectorData{Users: []types.User{u}, Groups: nil}

	f := NewDnsAdminsMemberDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (no DnsAdmins group collected: fails closed)", f.Count)
	}
}

// TestDnsAdminsMember_CaseInsensitiveSAMAccountNameFlagged proves the
// sAMAccountName comparison in dnsAdminsGroupDNs is case-insensitive: a
// group collected with a differently-cased sAMAccountName than the literal
// "DnsAdmins" must still be resolved as the real group.
//
// Mutation testee (M1), sur le detecteur : dans dnsAdminsGroupDNs, remplacer
// strings.EqualFold(g.SAMAccountName, "DnsAdmins") par
// g.SAMAccountName == "DnsAdmins" (comparaison sensible a la casse).
// Mesure : ce test rougit (Count = 0 au lieu de 1). Ligne restauree,
// verifiee par grep (aucun marqueur residuel dans le fichier
// livre).
func TestDnsAdminsMember_CaseInsensitiveSAMAccountNameFlagged(t *testing.T) {
	g := types.Group{
		SAMAccountName: "DNSADMINS",
		DN:             "cn=dnsadmins,cn=users,dc=example,dc=com",
	}
	u := types.User{
		SAMAccountName: "case-sam-member",
		MemberOf:       []string{"cn=dnsadmins,cn=users,dc=example,dc=com"},
	}
	data := &audit.DetectorData{Users: []types.User{u}, Groups: []types.Group{g}}

	f := NewDnsAdminsMemberDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (sAMAccountName comparison must be case-insensitive: \"DNSADMINS\" is the real group)", f.Count)
	}
}

// TestDnsAdminsMember_CaseInsensitiveMemberOfDNFlagged proves the
// memberOf-side DN comparison tolerates a user's memberOf DN being cased
// differently than the group's collected DN. The group's own DN is given
// already lowercase so this test is immune to a group-DN-side ToLower
// removal (M3) and isolates the memberOf-side ToLower (M2) specifically.
//
// Mutation testee (M2), sur le detecteur : dans isMemberOfDnsAdmins, remplacer
// dnsAdminsDNs[strings.ToLower(dn)] par dnsAdminsDNs[dn] (retrait du
// ToLower sur le DN de memberOf). Mesure : ce test rougit (Count = 0 au
// lieu de 1, le memberOf mixte ne correspond plus a la cle stockee, deja
// en minuscules). Ligne restauree, verifiee par grep.
func TestDnsAdminsMember_CaseInsensitiveMemberOfDNFlagged(t *testing.T) {
	g := types.Group{
		SAMAccountName: "DnsAdmins",
		DN:             "cn=dnsadmins,cn=users,dc=example,dc=com",
	}
	u := types.User{
		SAMAccountName: "case-dn-member",
		MemberOf:       []string{"CN=DnsAdmins,CN=Users,DC=example,DC=com"},
	}
	data := &audit.DetectorData{Users: []types.User{u}, Groups: []types.Group{g}}

	f := NewDnsAdminsMemberDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (memberOf DN comparison must be case-insensitive)", f.Count)
	}
}

// TestDnsAdminsMember_CaseInsensitiveGroupDNFlagged proves the group-side
// DN is lowercased when the resolved-DN set is built. The user's memberOf
// is given already lowercase so this test is immune to a memberOf-side
// ToLower removal (M2) and isolates the group-DN-side ToLower (M3)
// specifically.
//
// Mutation testee (M3), sur le detecteur : dans dnsAdminsGroupDNs, remplacer
// dns[strings.ToLower(g.DN)] = true par dns[g.DN] = true (retrait du
// ToLower sur le DN du groupe). Mesure : ce test rougit (Count = 0 au lieu
// de 1, la cle stockee reste en casse mixte et ne correspond plus au
// memberOf, deja en minuscules). Ligne restauree, verifiee par grep.
func TestDnsAdminsMember_CaseInsensitiveGroupDNFlagged(t *testing.T) {
	g := types.Group{
		SAMAccountName: "DnsAdmins",
		DN:             "CN=DnsAdmins,CN=Users,DC=example,DC=com",
	}
	u := types.User{
		SAMAccountName: "case-group-dn-member",
		MemberOf:       []string{"cn=dnsadmins,cn=users,dc=example,dc=com"},
	}
	data := &audit.DetectorData{Users: []types.User{u}, Groups: []types.Group{g}}

	f := NewDnsAdminsMemberDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (the resolved group DN must be lowercased)", f.Count)
	}
}

// TestDnsAdminsMember_SAMAccountNameNotCNMatched targets the specific
// mutation of resolving the real group by CN instead of sAMAccountName -
// the exact regression this ticket fixes, viewed from the resolution side:
// a group whose CN is "DnsAdmins" but whose sAMAccountName is something
// else must not resolve.
//
// Mutation testee (M4), sur le detecteur : dans dnsAdminsGroupDNs, remplacer
// strings.EqualFold(g.SAMAccountName, "DnsAdmins") par
// strings.EqualFold(g.CN, "DnsAdmins") (retour a une resolution par CN,
// la regression que ce ticket corrige). Mesure : ce test rougit (Count = 1
// au lieu de 0, puisque le CN du groupe jetable vaut bien "DnsAdmins").
// Ligne restauree, verifiee par grep.
func TestDnsAdminsMember_SAMAccountNameNotCNMatched(t *testing.T) {
	g := types.Group{
		CN:             "DnsAdmins",
		SAMAccountName: "t377-dns-homonyme",
		DN:             "CN=DnsAdmins,OU=T377-Dns,DC=example,DC=com",
	}
	u := types.User{
		SAMAccountName: "cn-only-member",
		MemberOf:       []string{"CN=DnsAdmins,OU=T377-Dns,DC=example,DC=com"},
	}
	data := &audit.DetectorData{Users: []types.User{u}, Groups: []types.Group{g}}

	f := NewDnsAdminsMemberDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (resolution must read sAMAccountName, not CN: CN=\"DnsAdmins\" with a different sAMAccountName is the homonym, not the real group)", f.Count)
	}
}

// TestDnsAdminsMember_EmptyMemberOfNotFlagged is the empty baseline: a user
// with no memberOf entries at all must not be counted, even when a real
// DnsAdmins group IS collected (proves the empty check, not just an empty
// resolved set).
func TestDnsAdminsMember_EmptyMemberOfNotFlagged(t *testing.T) {
	g := types.Group{
		SAMAccountName: "DnsAdmins",
		DN:             "CN=DnsAdmins,CN=Users,DC=example,DC=com",
	}
	u := types.User{
		SAMAccountName: "no-groups-member",
		MemberOf:       nil,
	}
	data := &audit.DetectorData{Users: []types.User{u}, Groups: []types.Group{g}}

	f := NewDnsAdminsMemberDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (empty memberOf, even with a real DnsAdmins group present)", f.Count)
	}
}

// TestDnsAdminsMember_DisabledUserStillFlagged locks the declared absence of
// a state filter (Detect ranges over data.Users with no Disabled check): a
// disabled direct member of the real DnsAdmins group must still be counted,
// since membership itself - not the ability to currently authenticate - is
// the risk (membership resumes full effect the instant the account is
// re-enabled).
func TestDnsAdminsMember_DisabledUserStillFlagged(t *testing.T) {
	g := types.Group{
		SAMAccountName: "DnsAdmins",
		DN:             "CN=DnsAdmins,CN=Users,DC=example,DC=com",
	}
	u := types.User{
		SAMAccountName: "disabled-member",
		Disabled:       true,
		MemberOf:       []string{"CN=DnsAdmins,CN=Users,DC=example,DC=com"},
	}
	data := &audit.DetectorData{Users: []types.User{u}, Groups: []types.Group{g}}

	f := NewDnsAdminsMemberDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (no state filter: a disabled member of the real group is still counted)", f.Count)
	}
}

// TestDnsAdminsMember_TypeAndSeverity locks the finding's identifying
// fields.
//
// Mutation testee (M6), sur le detecteur : remplacer types.SeverityHigh par
// types.SeverityMedium dans Detect. Mesure : ce test rougit sur
// l'assertion de severite. Ligne restauree, verifiee par grep.
//
// Mutation testee (M7), sur le detecteur : remplacer le litteral "DNS_ADMINS_MEMBER" par
// "DNS_ADMINS_MEMBER_X" dans NewDnsAdminsMemberDetector. Mesure : ce test
// rougit sur l'assertion de type. Ligne restauree, verifiee par grep.
func TestDnsAdminsMember_TypeAndSeverity(t *testing.T) {
	data := &audit.DetectorData{}
	f := NewDnsAdminsMemberDetector().Detect(context.Background(), data)[0]
	if f.Type != "DNS_ADMINS_MEMBER" {
		t.Fatalf("Type = %q, want %q", f.Type, "DNS_ADMINS_MEMBER")
	}
	if f.Severity != types.SeverityHigh {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityHigh)
	}
}

// TestDnsAdminsMember_IncludeDetailsTrueHasEntities proves that with
// IncludeDetails=true, AffectedEntities is populated with exactly the DN of
// the real-group member.
func TestDnsAdminsMember_IncludeDetailsTrueHasEntities(t *testing.T) {
	g := types.Group{
		SAMAccountName: "DnsAdmins",
		DN:             "CN=DnsAdmins,CN=Users,DC=example,DC=com",
	}
	u := types.User{
		DN:             "CN=details-member,CN=Users,DC=example,DC=com",
		SAMAccountName: "details-member",
		MemberOf:       []string{"CN=DnsAdmins,CN=Users,DC=example,DC=com"},
	}
	data := &audit.DetectorData{Users: []types.User{u}, Groups: []types.Group{g}, IncludeDetails: true}

	f := NewDnsAdminsMemberDetector().Detect(context.Background(), data)[0]
	if len(f.AffectedEntities) != 1 {
		t.Fatalf("len(AffectedEntities) = %d, want 1 (IncludeDetails=true must populate entities)", len(f.AffectedEntities))
	}
	if f.AffectedEntities[0].DN != u.DN {
		t.Fatalf("AffectedEntities[0].DN = %q, want %q", f.AffectedEntities[0].DN, u.DN)
	}
}

// TestDnsAdminsMember_IncludeDetailsFalseNoEntities proves that with
// IncludeDetails=false, AffectedEntities stays empty even though the same
// user is counted (Count=1).
//
// Mutation testee (M8), sur le detecteur : dans Detect, remplacer
// `if data.IncludeDetails && len(affected) > 0` par
// `if len(affected) > 0` (retrait de la garde IncludeDetails). Mesure : ce
// test rougit (AffectedEntities se peuple malgre IncludeDetails=false) ;
// TestDnsAdminsMember_IncludeDetailsTrueHasEntities reste vert (son propre
// cas n'est pas affecte par le retrait d'une garde qui etait deja vraie
// pour lui). Ligne restauree, verifiee par grep.
func TestDnsAdminsMember_IncludeDetailsFalseNoEntities(t *testing.T) {
	g := types.Group{
		SAMAccountName: "DnsAdmins",
		DN:             "CN=DnsAdmins,CN=Users,DC=example,DC=com",
	}
	u := types.User{
		DN:             "CN=details-member,CN=Users,DC=example,DC=com",
		SAMAccountName: "details-member",
		MemberOf:       []string{"CN=DnsAdmins,CN=Users,DC=example,DC=com"},
	}
	data := &audit.DetectorData{Users: []types.User{u}, Groups: []types.Group{g}, IncludeDetails: false}

	f := NewDnsAdminsMemberDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (member still counted regardless of IncludeDetails)", f.Count)
	}
	if len(f.AffectedEntities) != 0 {
		t.Fatalf("len(AffectedEntities) = %d, want 0 (IncludeDetails=false must not populate entities)", len(f.AffectedEntities))
	}
}
