package delegation

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const inAdminGroupDomainDN = "DC=example,DC=com"

// groupObject is a small helper building a *audit.ObjectMeta entry keyed by
// SID, for tests that need privgroups.DNsBySIDSuffix to resolve a group.
func groupObject(dn, sid string) map[string]*audit.ObjectMeta {
	return map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}}
}

// TestInAdminGroup_HomonymNeverMatches is the false-positive case measured
// live against a real domain controller: a group whose CN is literally one
// of the ten protected names, placed anywhere in the directory with an
// ORDINARY domain RID (not one of the ten suffixes), must never flag a
// computer that is only a member of it. One sub-test per protected name.
func TestInAdminGroup_HomonymNeverMatches(t *testing.T) {
	names := []string{
		"Account Operators", "Administrators", "Backup Operators", "Domain Admins",
		"Domain Controllers", "Enterprise Admins", "Enterprise Key Admins", "Key Admins",
		"Print Operators", "Schema Admins", "Server Operators",
	}
	for _, name := range names {
		name := name
		t.Run(name, func(t *testing.T) {
			fakeDN := "CN=" + name + ",CN=Users," + inAdminGroupDomainDN
			fakeSID := "S-1-5-21-1111111111-2222222222-3333333333-94115" // ordinary RID, not any of the 10 suffixes
			c := types.Computer{
				DN:       "CN=WKS-" + name + "," + inAdminGroupDomainDN,
				MemberOf: []string{fakeDN},
			}
			data := &audit.DetectorData{
				Computers:   []types.Computer{c},
				ObjectBySID: groupObject(fakeDN, fakeSID),
			}
			f := NewInAdminGroupDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("homonym %q with an ordinary RID must not flag the computer, got Count=%d", name, f.Count)
			}
		})
	}
}

// TestInAdminGroup_RenamedLocalizedGroupStillFlagged proves the match is by
// SID, not by English CN: the real Domain Admins group (RID suffix -512),
// renamed to its French localized display name, must still be caught.
func TestInAdminGroup_RenamedLocalizedGroupStillFlagged(t *testing.T) {
	localizedDN := "CN=Admins du domaine,CN=Users," + inAdminGroupDomainDN
	realSID := "S-1-5-21-1111111111-2222222222-3333333333-512"
	c := types.Computer{
		DN:       "CN=WKS01," + inAdminGroupDomainDN,
		MemberOf: []string{localizedDN},
	}
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers:      []types.Computer{c},
		ObjectBySID:    groupObject(localizedDN, realSID),
	}
	f := NewInAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("real Domain Admins group (S-1-...-512) under a localized name must still flag the computer, got Count=%d, want 1", f.Count)
	}
}

// TestInAdminGroup_ExactGroupSet is the table-driven exact-set lock: inSet
// is inAdminGroupSIDSuffixes' 11 suffixes, written here as a literal (never
// read from the package var), split by the SID shape each really carries in
// a directory - domain-prefixed for the five domain-wide groups, real
// Builtin (S-1-5-32-5xx) for the five Builtin ones. A fixture that gave the
// Builtin groups a domain-prefixed SID instead (S-1-5-21-...-5xx) would
// still pass, since the code matches by suffix alone - but no real directory
// has ever shown a Builtin group under a domain SID (RIDs 544-551 exist
// only under S-1-5-32 in any AD forest), so that fixture would lock the
// "suffix" implementation choice instead of the semantics it is meant to
// pin, and would reject a stricter, equally-correct match on the real SID.
// outOfSet adds neighboring RIDs a naive substring or prefix match could
// confuse with an in-set suffix, plus a dash-stripped variant to prove the
// match requires the leading dash.
func TestInAdminGroup_ExactGroupSet(t *testing.T) {
	inSetDomain := []string{"-512", "-516", "-519", "-527", "-526"}
	inSetBuiltin := []string{"-548", "-544", "-551", "-550", "-549"}
	outOfSet := []struct {
		name   string
		suffix string
	}{
		{"Domain_Users_-513", "-513"},
		{"Domain_Computers_-515", "-515"},
		{"RODC_-521", "-521"},
		{"Replicator_S-1-5-32-552", "S-1-5-32-552"},
		{"neighbor_-1512_no_dash_confusion", "-1512"},
	}

	for _, suffix := range inSetDomain {
		suffix := suffix
		t.Run("in_set"+suffix, func(t *testing.T) {
			dn := "CN=Group" + suffix + ",CN=Users," + inAdminGroupDomainDN
			sid := "S-1-5-21-9999999999-8888888888-7777777777" + suffix
			c := types.Computer{DN: "CN=WKS" + suffix + "," + inAdminGroupDomainDN, MemberOf: []string{dn}}
			data := &audit.DetectorData{
				Computers:   []types.Computer{c},
				ObjectBySID: groupObject(dn, sid),
			}
			f := NewInAdminGroupDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("suffix %s is in inAdminGroupSIDSuffixes; membership must flag the computer, got Count=%d, want 1", suffix, f.Count)
			}
		})
	}

	for _, suffix := range inSetBuiltin {
		suffix := suffix
		t.Run("in_set"+suffix, func(t *testing.T) {
			dn := "CN=Group" + suffix + ",CN=Builtin," + inAdminGroupDomainDN
			sid := "S-1-5-32" + suffix
			c := types.Computer{DN: "CN=WKS" + suffix + "," + inAdminGroupDomainDN, MemberOf: []string{dn}}
			data := &audit.DetectorData{
				Computers:   []types.Computer{c},
				ObjectBySID: groupObject(dn, sid),
			}
			f := NewInAdminGroupDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("suffix %s is in inAdminGroupSIDSuffixes; membership must flag the computer, got Count=%d, want 1", suffix, f.Count)
			}
		})
	}

	for _, tc := range outOfSet {
		tc := tc
		t.Run("out_of_set_"+tc.name, func(t *testing.T) {
			var sid string
			if tc.suffix[0] == 'S' {
				sid = tc.suffix
			} else {
				sid = "S-1-5-21-9999999999-8888888888-7777777777" + tc.suffix
			}
			dn := "CN=Group" + tc.name + ",CN=Users," + inAdminGroupDomainDN
			c := types.Computer{DN: "CN=WKS-" + tc.name + "," + inAdminGroupDomainDN, MemberOf: []string{dn}}
			data := &audit.DetectorData{
				Computers:   []types.Computer{c},
				ObjectBySID: groupObject(dn, sid),
			}
			f := NewInAdminGroupDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("suffix %s is NOT in inAdminGroupSIDSuffixes; membership must not flag the computer, got Count=%d, want 0", tc.suffix, f.Count)
			}
		})
	}
}

// TestInAdminGroup_DisabledExcluded_ActiveIncluded partitions the same
// group membership on Computer.Disabled in both directions.
func TestInAdminGroup_DisabledExcluded_ActiveIncluded(t *testing.T) {
	dn := "CN=Key Admins,CN=Users," + inAdminGroupDomainDN
	sid := "S-1-5-21-1111111111-2222222222-3333333333-526"

	t.Run("active computer is flagged", func(t *testing.T) {
		c := types.Computer{DN: "CN=WKSACTIVE," + inAdminGroupDomainDN, MemberOf: []string{dn}, Disabled: false}
		data := &audit.DetectorData{Computers: []types.Computer{c}, ObjectBySID: groupObject(dn, sid)}
		f := NewInAdminGroupDetector().Detect(context.Background(), data)[0]
		if f.Count != 1 {
			t.Fatalf("active computer member must be flagged, got Count=%d, want 1", f.Count)
		}
	})

	t.Run("disabled computer is excluded", func(t *testing.T) {
		c := types.Computer{DN: "CN=WKSDISABLED," + inAdminGroupDomainDN, MemberOf: []string{dn}, Disabled: true}
		data := &audit.DetectorData{Computers: []types.Computer{c}, ObjectBySID: groupObject(dn, sid)}
		f := NewInAdminGroupDetector().Detect(context.Background(), data)[0]
		if f.Count != 0 {
			t.Fatalf("disabled computer member must be excluded from the Critical detector, got Count=%d, want 0", f.Count)
		}
	})
}

// TestInAdminGroup_DomainControllerOwnGroupNotFlagged: a real domain
// controller's computer account carries "Domain Controllers" (-516) as its
// primaryGroupID, an attribute this detector - and the collection layer
// feeding it - never reads for computer objects. Measured live across
// several domain controllers on two forests: every one of them had Domain
// Controllers ABSENT from MemberOf, never present. A DC's MemberOf instead
// carries whatever ordinary groups it happens to also belong to (Cert
// Publishers, in a default install). This fixture reflects that measured
// shape; a fixture that instead put the group's own DN into a DC's MemberOf
// (a shape no real DC has ever been observed to have) would prove nothing
// about real directories once -516 joined the matched set below.
func TestInAdminGroup_DomainControllerOwnGroupNotFlagged(t *testing.T) {
	certPublishersDN := "CN=Cert Publishers,CN=Users," + inAdminGroupDomainDN
	certPublishersSID := "S-1-5-21-1111111111-2222222222-3333333333-517"
	c := types.Computer{
		DN:       "CN=DC01,OU=Domain Controllers," + inAdminGroupDomainDN,
		MemberOf: []string{certPublishersDN},
	}
	data := &audit.DetectorData{Computers: []types.Computer{c}, ObjectBySID: groupObject(certPublishersDN, certPublishersSID)}
	f := NewInAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0: a real DC's MemberOf never carries Domain Controllers itself (that membership is by primaryGroupID, which this detector does not read) - only unrelated groups", f.Count)
	}
}

// TestInAdminGroup_NonDCComputerExplicitlyInDomainControllersFlagged proves
// the coverage this fix closes: an ordinary, non-DC computer added
// EXPLICITLY to "Domain Controllers" (-516) - the one shape no real DC ever
// takes, per the measurement above - is now caught. Before -516 joined
// inAdminGroupSIDSuffixes, this same fixture returned Count=0.
func TestInAdminGroup_NonDCComputerExplicitlyInDomainControllersFlagged(t *testing.T) {
	dn := "CN=Domain Controllers,CN=Users," + inAdminGroupDomainDN
	sid := "S-1-5-21-1111111111-2222222222-3333333333-516"
	c := types.Computer{
		DN:       "CN=WKS-NOT-A-DC," + inAdminGroupDomainDN,
		MemberOf: []string{dn},
	}
	data := &audit.DetectorData{IncludeDetails: true, Computers: []types.Computer{c}, ObjectBySID: groupObject(dn, sid)}
	f := NewInAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1: a non-DC computer explicitly added to Domain Controllers must be flagged", f.Count)
	}
}

// TestInAdminGroup_MembershipInTwoGroupsCountedOnce pins the no-duplicate
// property carried over from the pre-SID version: a computer in two of the
// ten groups is counted once, not twice.
func TestInAdminGroup_MembershipInTwoGroupsCountedOnce(t *testing.T) {
	daDN, daSID := "CN=Domain Admins,CN=Users,"+inAdminGroupDomainDN, "S-1-5-21-1-2-3-512"
	eaDN, eaSID := "CN=Enterprise Admins,CN=Users,"+inAdminGroupDomainDN, "S-1-5-21-1-2-3-519"
	c := types.Computer{
		DN:       "CN=WKS01," + inAdminGroupDomainDN,
		MemberOf: []string{daDN, eaDN},
	}
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers:      []types.Computer{c},
		ObjectBySID: map[string]*audit.ObjectMeta{
			daSID: {DN: daDN, SID: daSID, EntityType: types.EntityTypeGroup},
			eaSID: {DN: eaDN, SID: eaSID, EntityType: types.EntityTypeGroup},
		},
	}
	f := NewInAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (one computer, not one per matching group)", f.Count)
	}
	if len(f.AffectedEntities) != 1 {
		t.Fatalf("AffectedEntities = %d, want 1 (no duplicate entries for the same computer)", len(f.AffectedEntities))
	}
}

func TestInAdminGroup_SeverityIsCritical(t *testing.T) {
	f := NewInAdminGroupDetector().Detect(context.Background(), &audit.DetectorData{})[0]
	if f.Severity != types.SeverityCritical {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityCritical)
	}
}

func TestInAdminGroup_DescriptionTextLocked(t *testing.T) {
	want := "Enabled computer account is a direct member of a privileged group protected by AdminSDHolder (Domain Admins, Enterprise Admins, Administrators, Schema Admins, Account/Backup/Print/Server Operators, Key/Enterprise Key Admins, Domain Controllers), matched by SID so a same-named decoy group or a localized forest cannot hide or fake this membership. Domain Admins, Enterprise Admins and Administrators give direct domain compromise; the other groups give a documented escalation path through AD administration, DC replication or key-trust rights, and how exploitable it is depends on what else that group can reach in this directory. Disabled computer accounts in these groups are reported separately by COMPUTER_IN_ADMIN_GROUP_ON_DISABLED_ACCOUNT."
	f := NewInAdminGroupDetector().Detect(context.Background(), &audit.DetectorData{})[0]
	if f.Description != want {
		t.Fatalf("Description changed:\ngot:  %q\nwant: %q", f.Description, want)
	}
}
