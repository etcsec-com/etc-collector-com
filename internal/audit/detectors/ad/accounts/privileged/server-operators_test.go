package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const serverOperatorsRealDN = "CN=Server Operators,CN=Builtin,DC=corp,DC=local"

func serverOperatorsSIDIndex(dn string) map[string]*audit.ObjectMeta {
	return map[string]*audit.ObjectMeta{
		serverOperatorsSID: {DN: dn, SID: serverOperatorsSID, EntityType: types.EntityTypeGroup},
	}
}

// Server Operators on the lab DC had S-1-5-11 (Authenticated Users)
// as its only member. The old detector scanned data.Users[].MemberOf, found
// no user whose MemberOf mentioned "CN=Server Operators" (an FSP isn't a
// User), and stayed silent - a measured false negative, not theoretical.
func TestServerOperators_ForeignSecurityPrincipalMember_Detected(t *testing.T) {
	group := types.Group{
		DN: serverOperatorsRealDN,
		CN: "Server Operators",
		Members: []string{
			"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=corp,DC=local",
		},
	}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
		ObjectBySID:    serverOperatorsSIDIndex(serverOperatorsRealDN),
		IncludeDetails: true,
	}

	findings := NewServerOperatorsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("expected Count=1 (FSP member undetected by old MemberOf scan), got %d", f.Count)
	}
	if len(f.AffectedEntities) != 1 {
		t.Fatalf("expected 1 affected entity, got %d", len(f.AffectedEntities))
	}
	e := f.AffectedEntities[0]
	if e.Type != "foreignSecurityPrincipal" {
		t.Fatalf("expected type=foreignSecurityPrincipal, got %q", e.Type)
	}
	if e.SID != "S-1-5-11" {
		t.Fatalf("expected SID=S-1-5-11, got %q", e.SID)
	}
	if e.Name != "Authenticated Users" {
		t.Fatalf("expected well-known FSP to be labeled Authenticated Users, got %q", e.Name)
	}
}

func TestServerOperators_NestedGroupMember_Detected(t *testing.T) {
	nested := types.Group{
		DN:             "CN=IT Support,CN=Users,DC=corp,DC=local",
		CN:             "IT Support",
		SAMAccountName: "IT Support",
	}
	group := types.Group{
		DN:      serverOperatorsRealDN,
		CN:      "Server Operators",
		Members: []string{nested.DN},
	}
	data := &audit.DetectorData{
		Groups:         []types.Group{group, nested},
		ObjectBySID:    serverOperatorsSIDIndex(serverOperatorsRealDN),
		IncludeDetails: true,
	}

	findings := NewServerOperatorsDetector().Detect(context.Background(), data)
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("expected Count=1 (nested group member), got %d", f.Count)
	}
	if f.AffectedEntities[0].Type != "group" {
		t.Fatalf("expected type=group for nested group member, got %q", f.AffectedEntities[0].Type)
	}
}

func TestServerOperators_EmptyGroup_NoFinding(t *testing.T) {
	group := types.Group{
		DN: serverOperatorsRealDN,
		CN: "Server Operators",
	}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
		ObjectBySID:    serverOperatorsSIDIndex(serverOperatorsRealDN),
		IncludeDetails: true,
	}

	findings := NewServerOperatorsDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 for empty group, got %d", findings[0].Count)
	}
}

func TestServerOperators_GroupNotCollected_NoFinding(t *testing.T) {
	data := &audit.DetectorData{IncludeDetails: true}

	findings := NewServerOperatorsDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 when the group itself wasn't collected, got %d", findings[0].Count)
	}
}

// TestServerOperators_HomonymGroupNotFlagged_BothOrders is the homonym
// case this ticket fixes: a group literally named "Server Operators" but
// placed outside CN=Builtin, carrying an ordinary domain RID (not -549),
// must never contribute its members - in either slice order. Before this
// ticket, FindBuiltinGroup(data.Groups, "Server Operators") returned
// whichever of the two came first by CN/sAMAccountName match.
func TestServerOperators_HomonymGroupNotFlagged_BothOrders(t *testing.T) {
	real := types.Group{DN: serverOperatorsRealDN, CN: "Server Operators", Members: []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=corp,DC=local"}}
	decoyUserDN := "CN=Decoy,CN=Users,DC=corp,DC=local"
	decoy := types.Group{DN: "CN=Server Operators,CN=Users,DC=corp,DC=local", CN: "Server Operators", SAMAccountName: "Server Operators", Members: []string{decoyUserDN}}
	users := []types.User{{DN: decoyUserDN, SAMAccountName: "decoy"}}

	t.Run("decoy_first", func(t *testing.T) {
		data := &audit.DetectorData{
			Groups:         []types.Group{decoy, real},
			Users:          users,
			ObjectBySID:    serverOperatorsSIDIndex(serverOperatorsRealDN),
			IncludeDetails: true,
		}
		f := NewServerOperatorsDetector().Detect(context.Background(), data)[0]
		if f.Count != 1 {
			t.Fatalf("Count = %d, want 1 (only the real group's FSP, decoy first in slice)", f.Count)
		}
		if f.AffectedEntities[0].Type != "foreignSecurityPrincipal" {
			t.Fatalf("expected the real group's FSP member, got %+v", f.AffectedEntities[0])
		}
	})

	t.Run("decoy_second", func(t *testing.T) {
		data := &audit.DetectorData{
			Groups:         []types.Group{real, decoy},
			Users:          users,
			ObjectBySID:    serverOperatorsSIDIndex(serverOperatorsRealDN),
			IncludeDetails: true,
		}
		f := NewServerOperatorsDetector().Detect(context.Background(), data)[0]
		if f.Count != 1 {
			t.Fatalf("Count = %d, want 1 (only the real group's FSP, decoy second in slice)", f.Count)
		}
		if f.AffectedEntities[0].Type != "foreignSecurityPrincipal" {
			t.Fatalf("expected the real group's FSP member, got %+v", f.AffectedEntities[0])
		}
	})
}

// TestServerOperators_RenamedLocalizedGroupStillFlagged confirms the real
// group is still found under its French display name, since resolution no
// longer depends on the name at all.
func TestServerOperators_RenamedLocalizedGroupStillFlagged(t *testing.T) {
	localizedDN := "CN=Opérateurs de serveur,CN=Builtin,DC=corp,DC=local"
	group := types.Group{
		DN:      localizedDN,
		CN:      "Opérateurs de serveur",
		Members: []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=corp,DC=local"},
	}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
		ObjectBySID:    serverOperatorsSIDIndex(localizedDN),
		IncludeDetails: true,
	}

	f := NewServerOperatorsDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (localized group name must still be flagged)", f.Count)
	}
}

// TestServerOperators_ExactGroupSet locks the SID this detector matches to
// -549 alone: a neighbor RID (-548 Account Operators, -550 Print Operators,
// -551 Backup Operators) must never be treated as Server Operators.
func TestServerOperators_ExactGroupSet(t *testing.T) {
	cases := []struct {
		name      string
		sid       string
		wantCount int
	}{
		{"in_set--549", "S-1-5-32-549", 1},
		{"out_of_set--548", "S-1-5-32-548", 0},
		{"out_of_set--550", "S-1-5-32-550", 0},
		{"out_of_set--551", "S-1-5-32-551", 0},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dn := "CN=Group" + tc.sid + ",CN=Builtin,DC=corp,DC=local"
			group := types.Group{
				DN:      dn,
				Members: []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=corp,DC=local"},
			}
			data := &audit.DetectorData{
				Groups:         []types.Group{group},
				ObjectBySID:    map[string]*audit.ObjectMeta{tc.sid: {DN: dn, SID: tc.sid, EntityType: types.EntityTypeGroup}},
				IncludeDetails: true,
			}
			f := NewServerOperatorsDetector().Detect(context.Background(), data)[0]
			if f.Count != tc.wantCount {
				t.Fatalf("SID %s: Count = %d, want %d", tc.sid, f.Count, tc.wantCount)
			}
		})
	}
}

// TestServerOperators_DisabledUserExcluded_ActiveIncluded is the partition
// guard from this detector's side, for a user member: a disabled direct
// member must not be counted here - it belongs to
// ServerOperatorsOnDisabledAccountDetector instead. An active member in the
// same group stays counted.
func TestServerOperators_DisabledUserExcluded_ActiveIncluded(t *testing.T) {
	activeDN := "CN=Active,CN=Users,DC=corp,DC=local"
	disabledDN := "CN=Disabled,CN=Users,DC=corp,DC=local"
	group := types.Group{DN: serverOperatorsRealDN, Members: []string{activeDN, disabledDN}}
	data := &audit.DetectorData{
		Groups: []types.Group{group},
		Users: []types.User{
			{DN: activeDN, SAMAccountName: "active"},
			{DN: disabledDN, SAMAccountName: "disabled", Disabled: true},
		},
		ObjectBySID:    serverOperatorsSIDIndex(serverOperatorsRealDN),
		IncludeDetails: true,
	}

	f := NewServerOperatorsDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (only the active user)", f.Count)
	}
	if f.AffectedEntities[0].DN != activeDN {
		t.Fatalf("expected the active member %q, got %q", activeDN, f.AffectedEntities[0].DN)
	}
}

// TestServerOperators_DisabledComputerExcluded_ActiveIncluded is the
// computer-side mirror of TestServerOperators_DisabledUserExcluded_ActiveIncluded.
func TestServerOperators_DisabledComputerExcluded_ActiveIncluded(t *testing.T) {
	activeDN := "CN=ACTIVE1,CN=Computers,DC=corp,DC=local"
	disabledDN := "CN=DISABLED1,CN=Computers,DC=corp,DC=local"
	group := types.Group{DN: serverOperatorsRealDN, Members: []string{activeDN, disabledDN}}
	data := &audit.DetectorData{
		Groups: []types.Group{group},
		Computers: []types.Computer{
			{DN: activeDN, SAMAccountName: "ACTIVE1$"},
			{DN: disabledDN, SAMAccountName: "DISABLED1$", Disabled: true},
		},
		ObjectBySID:    serverOperatorsSIDIndex(serverOperatorsRealDN),
		IncludeDetails: true,
	}

	f := NewServerOperatorsDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (only the active computer)", f.Count)
	}
	if f.AffectedEntities[0].DN != activeDN {
		t.Fatalf("expected the active member %q, got %q", activeDN, f.AffectedEntities[0].DN)
	}
}

// TestServerOperators_FSPAndNestedGroupStayHighRegardlessOfDisabledFilter
// confirms the Disabled filter only ever excludes user/computer kinds: a
// FSP and a nested group have no UserAccountControl and must remain High
// alongside an unrelated disabled user in the same group.
func TestServerOperators_FSPAndNestedGroupStayHighRegardlessOfDisabledFilter(t *testing.T) {
	fspDN := "CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=corp,DC=local"
	nestedDN := "CN=IT Support,CN=Users,DC=corp,DC=local"
	disabledUserDN := "CN=Disabled,CN=Users,DC=corp,DC=local"
	group := types.Group{DN: serverOperatorsRealDN, Members: []string{fspDN, nestedDN, disabledUserDN}}
	nested := types.Group{DN: nestedDN, CN: "IT Support", SAMAccountName: "IT Support"}
	data := &audit.DetectorData{
		Groups:         []types.Group{group, nested},
		Users:          []types.User{{DN: disabledUserDN, SAMAccountName: "disabled", Disabled: true}},
		ObjectBySID:    serverOperatorsSIDIndex(serverOperatorsRealDN),
		IncludeDetails: true,
	}

	f := NewServerOperatorsDetector().Detect(context.Background(), data)[0]
	if f.Count != 2 {
		t.Fatalf("Count = %d, want 2 (FSP + nested group, disabled user excluded)", f.Count)
	}
	var sawFSP, sawGroup bool
	for _, e := range f.AffectedEntities {
		if e.Type == "foreignSecurityPrincipal" {
			sawFSP = true
		}
		if e.Type == "group" {
			sawGroup = true
		}
		if e.DN == disabledUserDN {
			t.Fatalf("disabled user %q must not appear in the High finding", disabledUserDN)
		}
	}
	if !sawFSP || !sawGroup {
		t.Fatalf("expected both a foreignSecurityPrincipal and a group entity, got %+v", f.AffectedEntities)
	}
}

// TestServerOperators_SeverityIsHigh locks the active-member finding's
// severity: the split must not silently change it.
func TestServerOperators_SeverityIsHigh(t *testing.T) {
	group := types.Group{DN: serverOperatorsRealDN, Members: []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=corp,DC=local"}}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
		ObjectBySID:    serverOperatorsSIDIndex(serverOperatorsRealDN),
		IncludeDetails: true,
	}

	f := NewServerOperatorsDetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityHigh {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityHigh)
	}
}

// TestServerOperators_DescriptionTextLocked locks the Detect()-side
// Description text against silent drift. TestCatalogIsStable only compares
// Doc() (docs_gen.go) to the committed markdown catalog and cannot see a
// divergence between Doc() and Detect().
func TestServerOperators_DescriptionTextLocked(t *testing.T) {
	group := types.Group{DN: serverOperatorsRealDN, Members: []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=corp,DC=local"}}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
		ObjectBySID:    serverOperatorsSIDIndex(serverOperatorsRealDN),
		IncludeDetails: true,
	}

	want := "Active (non-disabled) real members of the Server Operators group: users, nested groups, computers, and foreign security principals. Members can sign in interactively to domain controllers, create and delete shared resources, stop and start services, back up and restore files, format the hard disk, and shut down the domain controller. A broad foreign security principal (e.g. Authenticated Users, Everyone) means the privilege is effectively unrestricted. Disabled user and computer members are reported separately by SERVER_OPERATORS_MEMBER_ON_DISABLED_ACCOUNT."
	f := NewServerOperatorsDetector().Detect(context.Background(), data)[0]
	if f.Description != want {
		t.Fatalf("Description = %q, want %q", f.Description, want)
	}
}
