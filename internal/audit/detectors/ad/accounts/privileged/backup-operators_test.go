package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const backupOperatorsRealDN = "CN=Backup Operators,CN=Builtin,DC=corp,DC=local"

func backupOperatorsSIDIndex(dn string) map[string]*audit.ObjectMeta {
	return map[string]*audit.ObjectMeta{
		backupOperatorsSID: {DN: dn, SID: backupOperatorsSID, EntityType: types.EntityTypeGroup},
	}
}

// Backup Operators on the lab DC had S-1-1-0 (Everyone) as its only
// member. The old detector scanned data.Users[].MemberOf, found no user
// whose MemberOf mentioned "CN=Backup Operators" (an FSP isn't a User), and
// stayed silent - a measured false negative, not theoretical.
func TestBackupOperators_ForeignSecurityPrincipalMember_Detected(t *testing.T) {
	group := types.Group{
		DN: backupOperatorsRealDN,
		CN: "Backup Operators",
		Members: []string{
			"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=corp,DC=local",
		},
	}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
		ObjectBySID:    backupOperatorsSIDIndex(backupOperatorsRealDN),
		IncludeDetails: true,
	}

	findings := NewBackupOperatorsDetector().Detect(context.Background(), data)
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
	if e.SID != "S-1-1-0" {
		t.Fatalf("expected SID=S-1-1-0, got %q", e.SID)
	}
	if e.Name != "Everyone" {
		t.Fatalf("expected well-known FSP to be labeled Everyone, got %q", e.Name)
	}
}

func TestBackupOperators_ComputerMember_Detected(t *testing.T) {
	computer := types.Computer{
		DN:             "CN=SRV01,CN=Computers,DC=corp,DC=local",
		SAMAccountName: "SRV01$",
	}
	group := types.Group{
		DN:      backupOperatorsRealDN,
		CN:      "Backup Operators",
		Members: []string{computer.DN},
	}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
		Computers:      []types.Computer{computer},
		ObjectBySID:    backupOperatorsSIDIndex(backupOperatorsRealDN),
		IncludeDetails: true,
	}

	findings := NewBackupOperatorsDetector().Detect(context.Background(), data)
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("expected Count=1 (computer member), got %d", f.Count)
	}
	if f.AffectedEntities[0].Type != "computer" {
		t.Fatalf("expected type=computer, got %q", f.AffectedEntities[0].Type)
	}
}

func TestBackupOperators_EmptyGroup_NoFinding(t *testing.T) {
	group := types.Group{
		DN: backupOperatorsRealDN,
		CN: "Backup Operators",
	}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
		ObjectBySID:    backupOperatorsSIDIndex(backupOperatorsRealDN),
		IncludeDetails: true,
	}

	findings := NewBackupOperatorsDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 for empty group, got %d", findings[0].Count)
	}
}

func TestBackupOperators_GroupNotCollected_NoFinding(t *testing.T) {
	data := &audit.DetectorData{IncludeDetails: true}

	findings := NewBackupOperatorsDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 when the group itself wasn't collected, got %d", findings[0].Count)
	}
}

// TestBackupOperators_HomonymGroupNotFlagged_BothOrders is the homonym
// case this ticket fixes: a group literally named "Backup Operators" but
// placed outside CN=Builtin, carrying an ordinary domain RID (not -551),
// must never contribute its members - in either slice order. Before this
// ticket, FindBuiltinGroup(data.Groups, "Backup Operators") returned
// whichever of the two came first by CN/sAMAccountName match.
func TestBackupOperators_HomonymGroupNotFlagged_BothOrders(t *testing.T) {
	real := types.Group{DN: backupOperatorsRealDN, CN: "Backup Operators", Members: []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=corp,DC=local"}}
	decoyUserDN := "CN=Decoy,CN=Users,DC=corp,DC=local"
	decoy := types.Group{DN: "CN=Backup Operators,CN=Users,DC=corp,DC=local", CN: "Backup Operators", SAMAccountName: "Backup Operators", Members: []string{decoyUserDN}}
	users := []types.User{{DN: decoyUserDN, SAMAccountName: "decoy"}}

	t.Run("decoy_first", func(t *testing.T) {
		data := &audit.DetectorData{
			Groups:         []types.Group{decoy, real},
			Users:          users,
			ObjectBySID:    backupOperatorsSIDIndex(backupOperatorsRealDN),
			IncludeDetails: true,
		}
		f := NewBackupOperatorsDetector().Detect(context.Background(), data)[0]
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
			ObjectBySID:    backupOperatorsSIDIndex(backupOperatorsRealDN),
			IncludeDetails: true,
		}
		f := NewBackupOperatorsDetector().Detect(context.Background(), data)[0]
		if f.Count != 1 {
			t.Fatalf("Count = %d, want 1 (only the real group's FSP, decoy second in slice)", f.Count)
		}
		if f.AffectedEntities[0].Type != "foreignSecurityPrincipal" {
			t.Fatalf("expected the real group's FSP member, got %+v", f.AffectedEntities[0])
		}
	})
}

// TestBackupOperators_RenamedLocalizedGroupStillFlagged confirms the real
// group is still found under its French display name, since resolution no
// longer depends on the name at all.
func TestBackupOperators_RenamedLocalizedGroupStillFlagged(t *testing.T) {
	localizedDN := "CN=Opérateurs de sauvegarde,CN=Builtin,DC=corp,DC=local"
	group := types.Group{
		DN:      localizedDN,
		CN:      "Opérateurs de sauvegarde",
		Members: []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=corp,DC=local"},
	}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
		ObjectBySID:    backupOperatorsSIDIndex(localizedDN),
		IncludeDetails: true,
	}

	f := NewBackupOperatorsDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (localized group name must still be flagged)", f.Count)
	}
}

// TestBackupOperators_ExactGroupSet locks the SID this detector matches to
// -551 alone: a neighbor RID (-548 Account Operators, -549 Server
// Operators, -550 Print Operators) must never be treated as Backup
// Operators.
func TestBackupOperators_ExactGroupSet(t *testing.T) {
	cases := []struct {
		name      string
		sid       string
		wantCount int
	}{
		{"in_set--551", "S-1-5-32-551", 1},
		{"out_of_set--548", "S-1-5-32-548", 0},
		{"out_of_set--549", "S-1-5-32-549", 0},
		{"out_of_set--550", "S-1-5-32-550", 0},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dn := "CN=Group" + tc.sid + ",CN=Builtin,DC=corp,DC=local"
			group := types.Group{
				DN:      dn,
				Members: []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=corp,DC=local"},
			}
			data := &audit.DetectorData{
				Groups:         []types.Group{group},
				ObjectBySID:    map[string]*audit.ObjectMeta{tc.sid: {DN: dn, SID: tc.sid, EntityType: types.EntityTypeGroup}},
				IncludeDetails: true,
			}
			f := NewBackupOperatorsDetector().Detect(context.Background(), data)[0]
			if f.Count != tc.wantCount {
				t.Fatalf("SID %s: Count = %d, want %d", tc.sid, f.Count, tc.wantCount)
			}
		})
	}
}

// TestBackupOperators_DisabledUserExcluded_ActiveIncluded is the partition
// guard from this detector's side, for a user member: a disabled direct
// member must not be counted here - it belongs to
// BackupOperatorsOnDisabledAccountDetector instead. An active member in the
// same group stays counted.
func TestBackupOperators_DisabledUserExcluded_ActiveIncluded(t *testing.T) {
	activeDN := "CN=Active,CN=Users,DC=corp,DC=local"
	disabledDN := "CN=Disabled,CN=Users,DC=corp,DC=local"
	group := types.Group{DN: backupOperatorsRealDN, Members: []string{activeDN, disabledDN}}
	data := &audit.DetectorData{
		Groups: []types.Group{group},
		Users: []types.User{
			{DN: activeDN, SAMAccountName: "active"},
			{DN: disabledDN, SAMAccountName: "disabled", Disabled: true},
		},
		ObjectBySID:    backupOperatorsSIDIndex(backupOperatorsRealDN),
		IncludeDetails: true,
	}

	f := NewBackupOperatorsDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (only the active user)", f.Count)
	}
	if f.AffectedEntities[0].DN != activeDN {
		t.Fatalf("expected the active member %q, got %q", activeDN, f.AffectedEntities[0].DN)
	}
}

// TestBackupOperators_DisabledComputerExcluded_ActiveIncluded is the
// computer-side mirror of TestBackupOperators_DisabledUserExcluded_ActiveIncluded.
func TestBackupOperators_DisabledComputerExcluded_ActiveIncluded(t *testing.T) {
	activeDN := "CN=ACTIVE1,CN=Computers,DC=corp,DC=local"
	disabledDN := "CN=DISABLED1,CN=Computers,DC=corp,DC=local"
	group := types.Group{DN: backupOperatorsRealDN, Members: []string{activeDN, disabledDN}}
	data := &audit.DetectorData{
		Groups: []types.Group{group},
		Computers: []types.Computer{
			{DN: activeDN, SAMAccountName: "ACTIVE1$"},
			{DN: disabledDN, SAMAccountName: "DISABLED1$", Disabled: true},
		},
		ObjectBySID:    backupOperatorsSIDIndex(backupOperatorsRealDN),
		IncludeDetails: true,
	}

	f := NewBackupOperatorsDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (only the active computer)", f.Count)
	}
	if f.AffectedEntities[0].DN != activeDN {
		t.Fatalf("expected the active member %q, got %q", activeDN, f.AffectedEntities[0].DN)
	}
}

// TestBackupOperators_FSPAndNestedGroupStayHighRegardlessOfDisabledFilter
// confirms the Disabled filter only ever excludes user/computer kinds: a
// FSP and a nested group have no UserAccountControl and must remain High
// alongside an unrelated disabled user in the same group.
func TestBackupOperators_FSPAndNestedGroupStayHighRegardlessOfDisabledFilter(t *testing.T) {
	fspDN := "CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=corp,DC=local"
	nestedDN := "CN=IT Support,CN=Users,DC=corp,DC=local"
	disabledUserDN := "CN=Disabled,CN=Users,DC=corp,DC=local"
	group := types.Group{DN: backupOperatorsRealDN, Members: []string{fspDN, nestedDN, disabledUserDN}}
	nested := types.Group{DN: nestedDN, CN: "IT Support", SAMAccountName: "IT Support"}
	data := &audit.DetectorData{
		Groups:         []types.Group{group, nested},
		Users:          []types.User{{DN: disabledUserDN, SAMAccountName: "disabled", Disabled: true}},
		ObjectBySID:    backupOperatorsSIDIndex(backupOperatorsRealDN),
		IncludeDetails: true,
	}

	f := NewBackupOperatorsDetector().Detect(context.Background(), data)[0]
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

// TestBackupOperators_SeverityIsHigh locks the active-member finding's
// severity: the split must not silently change it.
func TestBackupOperators_SeverityIsHigh(t *testing.T) {
	group := types.Group{DN: backupOperatorsRealDN, Members: []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=corp,DC=local"}}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
		ObjectBySID:    backupOperatorsSIDIndex(backupOperatorsRealDN),
		IncludeDetails: true,
	}

	f := NewBackupOperatorsDetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityHigh {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityHigh)
	}
}

// TestBackupOperators_DescriptionTextLocked locks the Detect()-side
// Description text against silent drift. TestCatalogIsStable only compares
// Doc() (docs_gen.go) to the committed markdown catalog and cannot see a
// divergence between Doc() and Detect().
func TestBackupOperators_DescriptionTextLocked(t *testing.T) {
	group := types.Group{DN: backupOperatorsRealDN, Members: []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=corp,DC=local"}}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
		ObjectBySID:    backupOperatorsSIDIndex(backupOperatorsRealDN),
		IncludeDetails: true,
	}

	want := "Active (non-disabled) real members of the Backup Operators group: users, nested groups, computers, and foreign security principals. Members can back up and restore all files on domain controllers regardless of the permissions protecting them, sign in interactively, log on as a batch job, and shut down the domain controller. Because they can replace any file - including OS files - on a domain controller, they are treated as service administrators with effective control comparable to Domain Admins, even though they cannot directly change server configuration or modify the membership of other administrative groups. A broad foreign security principal (e.g. Authenticated Users, Everyone) means the privilege is effectively unrestricted. Disabled user and computer members are reported separately by BACKUP_OPERATORS_MEMBER_ON_DISABLED_ACCOUNT."
	f := NewBackupOperatorsDetector().Detect(context.Background(), data)[0]
	if f.Description != want {
		t.Fatalf("Description = %q, want %q", f.Description, want)
	}
}
