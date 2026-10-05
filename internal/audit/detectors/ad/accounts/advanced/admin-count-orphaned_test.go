package advanced

import (
	"context"
	"strconv"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Microsoft Learn, "Appendix C: Protected Accounts and Groups in Active
// Directory" (learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/
// security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
// lists krbtgt as a protected ACCOUNT (adminCount=1 on it is normal,
// AdminSDHolder/SDProp behavior, never an orphan) and names 13 protected
// GROUPS beyond the 8 this detector used to check. Before the fix, krbtgt
// was flagged as "orphaned" and a user whose adminCount=1 came only from
// membership in one of the five missing groups (Domain Controllers,
// Read-only Domain Controllers, Replicator, Key Admins, Enterprise Key
// Admins) was flagged too.
func TestAdminCountOrphaned_KrbtgtNeverFlagged(t *testing.T) {
	u := types.User{
		SAMAccountName: "krbtgt",
		AdminCount:     true,
		ObjectSID:      "S-1-5-21-1111111111-2222222222-3333333333-502",
		// No group membership at all - the case that used to guarantee a flag.
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("krbtgt is protected by design (Appendix C), identified by RID (-502); it must never be flagged as orphaned, got Count=%d", f.Count)
	}
}

func TestAdminCountOrphaned_BuiltinAdministratorNeverFlagged(t *testing.T) {
	u := types.User{
		SAMAccountName: "Administrator",
		AdminCount:     true,
		ObjectSID:      "S-1-5-21-1111111111-2222222222-3333333333-500",
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("the built-in Administrator account is protected by design (Appendix C), identified by RID (-500); it must never be flagged as orphaned, got Count=%d", f.Count)
	}
}

// TestAdminCountOrphaned_AdministratorRenamedStillExempt is the renamed-RID
// case: a common hardening step renames the built-in Administrator account
// away from "administrator". Before the fix (name-based
// isProtectedAccountName), this account would have been wrongly flagged as
// orphaned the moment it was renamed. RID (-500) survives the rename.
func TestAdminCountOrphaned_AdministratorRenamedStillExempt(t *testing.T) {
	u := types.User{
		SAMAccountName: "svc-legacy-9f2",
		AdminCount:     true,
		ObjectSID:      "S-1-5-21-1111111111-2222222222-3333333333-500",
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("a renamed built-in Administrator account (RID -500) must still be exempt regardless of its current name, got Count=%d, want 0", f.Count)
	}
}

// TestAdminCountOrphaned_AccountNamedAdministratorOrdinaryRIDStillFlagged is
// the inverse of the rename case: an ORDINARY account that merely happens to
// be named "administrator" (an ordinary domain RID, not -500) carries no
// Appendix C protection at all and must still be flagged. Before the fix,
// the name-based check would have wrongly exempted it.
func TestAdminCountOrphaned_AccountNamedAdministratorOrdinaryRIDStillFlagged(t *testing.T) {
	u := types.User{
		SAMAccountName: "administrator",
		AdminCount:     true,
		ObjectSID:      "S-1-5-21-1111111111-2222222222-3333333333-9201",
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("an ordinary account merely named %q (RID -9201, not -500) carries no Appendix C protection; must be flagged, got Count=%d, want 1", u.SAMAccountName, f.Count)
	}
}

// TestAdminCountOrphaned_PrimaryGroupProtected covers both branches the
// primary-group exemption must reach: an empty memberOf, and a memberOf
// that is present but not itself protected. In both, a protected PRIMARY
// group (526 Key Admins, 512 Domain Admins) must exempt the account.
func TestAdminCountOrphaned_PrimaryGroupProtected(t *testing.T) {
	const domainSID = "S-1-5-21-1111111111-2222222222-3333333333"

	cases := []struct {
		name           string
		primaryGroupID int
		groupDN        string
		memberOf       []string
	}{
		{"KeyAdmins_EmptyMemberOf", 526, "CN=Key Admins,CN=Users,DC=corp,DC=local", nil},
		{"DomainAdmins_UnprotectedMemberOf", 512, "CN=Domain Admins,CN=Users,DC=corp,DC=local", []string{"CN=Marketing,CN=Users,DC=corp,DC=local"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			groupSID := domainSID + "-" + strconv.Itoa(tc.primaryGroupID)
			u := types.User{
				SAMAccountName: "member-" + tc.name,
				AdminCount:     true,
				PrimaryGroupID: tc.primaryGroupID,
				MemberOf:       tc.memberOf,
			}
			data := &audit.DetectorData{
				Users:      []types.User{u},
				DomainInfo: &types.DomainInfo{DomainSID: domainSID},
				ObjectBySID: map[string]*audit.ObjectMeta{
					groupSID: {DN: tc.groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
				},
			}

			f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("a protected primary group (RID %d) must exempt the account regardless of memberOf state, got Count=%d, want 0", tc.primaryGroupID, f.Count)
			}
		})
	}
}

// TestAdminCountOrphaned_PrimaryGroupOrdinaryRIDStillFlagged is the negative
// case: an ordinary primary group (Domain Users, 513) grants no exemption.
func TestAdminCountOrphaned_PrimaryGroupOrdinaryRIDStillFlagged(t *testing.T) {
	const domainSID = "S-1-5-21-1111111111-2222222222-3333333333"
	u := types.User{
		SAMAccountName: "ordinary-primary-group",
		AdminCount:     true,
		PrimaryGroupID: 513,
	}
	data := &audit.DetectorData{
		Users:      []types.User{u},
		DomainInfo: &types.DomainInfo{DomainSID: domainSID},
	}

	f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("an ordinary primary group (RID 513, Domain Users) must not exempt the account, got Count=%d, want 1", f.Count)
	}
}

// TestAdminCountOrphaned_SpoofedDomainLocalPrimaryGroupNotExempt guards the
// exact-match design: AD never accepts a domain-local builtin group
// (Administrators, RID -544, real SID S-1-5-32-544) as a primary group, but
// a raw write could still spoof PrimaryGroupID=544 (see
// accounts/patterns/primarygroupid-spoofing.go). Because primaryGroupIsProtected
// does an EXACT match on "<domainSID>-544" against data.ObjectBySID, and the
// real Administrators SID never has that form, no exemption must be granted
// even when the domain-relative SID happens to be present in the index
// under a different (correct) key.
func TestAdminCountOrphaned_SpoofedDomainLocalPrimaryGroupNotExempt(t *testing.T) {
	const domainSID = "S-1-5-21-1111111111-2222222222-3333333333"
	u := types.User{
		SAMAccountName: "spoofed-primary-group",
		AdminCount:     true,
		PrimaryGroupID: 544, // Administrators RID, never a legal primary group
	}
	data := &audit.DetectorData{
		Users:      []types.User{u},
		DomainInfo: &types.DomainInfo{DomainSID: domainSID},
		ObjectBySID: map[string]*audit.ObjectMeta{
			// The real Administrators group, at its real (non-domain-relative) SID.
			"S-1-5-32-544": {DN: "CN=Administrators,CN=Builtin,DC=corp,DC=local", SID: "S-1-5-32-544", EntityType: types.EntityTypeGroup},
		},
	}

	f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("a spoofed primaryGroupID=544 (Administrators, never a legal primary group) must not exempt the account, got Count=%d, want 1", f.Count)
	}
}

// TestAdminCountOrphaned_EmptyDomainSIDNoExemptionNoCrash is the explicit
// fail-closed case: without a domain SID, the primary group cannot be
// turned into a real SID, so no exemption is granted - the account still
// falls through to the memberOf-based checks. Must not panic either.
func TestAdminCountOrphaned_EmptyDomainSIDNoExemptionNoCrash(t *testing.T) {
	u := types.User{
		SAMAccountName: "no-domain-sid",
		AdminCount:     true,
		PrimaryGroupID: 512, // would otherwise be a protected primary group
	}
	data := &audit.DetectorData{
		Users:      []types.User{u},
		DomainInfo: &types.DomainInfo{DomainSID: ""},
	}

	f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("an empty domain SID must not grant a primary-group exemption (fail closed), got Count=%d, want 1", f.Count)
	}
}

// TestAdminCountOrphaned_ActiveDisabledPartition proves the split is exact:
// each account lands in exactly one of the two detectors, never both, never
// neither.
func TestAdminCountOrphaned_ActiveDisabledPartition(t *testing.T) {
	active := types.User{SAMAccountName: "active-orphan", AdminCount: true, Disabled: false}
	disabled := types.User{SAMAccountName: "disabled-orphan", AdminCount: true, Disabled: true}
	data := &audit.DetectorData{Users: []types.User{active, disabled}}

	activeFinding := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	if activeFinding.Count != 1 {
		t.Fatalf("ADMIN_COUNT_ORPHANED must count only the active orphan, got Count=%d, want 1", activeFinding.Count)
	}

	disabledFinding := NewAdminCountOrphanedOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if disabledFinding.Count != 1 {
		t.Fatalf("ADMIN_COUNT_ORPHANED_ON_DISABLED_ACCOUNT must count only the disabled orphan, got Count=%d, want 1", disabledFinding.Count)
	}
}

func TestAdminCountOrphaned_Severity(t *testing.T) {
	data := &audit.DetectorData{}
	f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityMedium {
		t.Fatalf("ADMIN_COUNT_ORPHANED (active accounts) must stay Medium, got %v", f.Severity)
	}
}

// TestAdminCountOrphaned_DescriptionLocked is a literal lock: the exact
// string below is typed independently of the source, not copied from a
// shared constant, so a change to the detector's Description fails this
// test rather than silently drifting.
func TestAdminCountOrphaned_DescriptionLocked(t *testing.T) {
	const want = "Active accounts with adminCount=1 that are not a DIRECT member - via memberOf or primary group - of any group AdminSDHolder/SDProp protects (Microsoft Learn, \"Appendix C: Protected Accounts and Groups in Active Directory\", https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory), and are not krbtgt or the built-in Administrator account (identified by RID, not name). May indicate a removed admin that still carries residual privileges, or intact SDProp protection. Limitation: membership reached through a NESTED group - a group that is itself a member of a protected group, or a primary group that is itself nested - is not resolved and can still produce a false positive here."

	data := &audit.DetectorData{}
	f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	if f.Description != want {
		t.Fatalf("ADMIN_COUNT_ORPHANED Description drifted from the locked text.\ngot:  %s\nwant: %s", f.Description, want)
	}
}

func TestAdminCountOrphaned_PreviouslyMissingProtectedGroups(t *testing.T) {
	cases := []struct {
		name  string
		group string
		sid   string
	}{
		{"Domain Controllers", "CN=Domain Controllers,CN=Users,DC=corp,DC=local", "S-1-5-21-1111111111-2222222222-3333333333-516"},
		{"Read-only Domain Controllers", "CN=Read-only Domain Controllers,CN=Users,DC=corp,DC=local", "S-1-5-21-1111111111-2222222222-3333333333-521"},
		{"Replicator", "CN=Replicator,CN=Builtin,DC=corp,DC=local", "S-1-5-32-552"},
		{"Key Admins", "CN=Key Admins,CN=Users,DC=corp,DC=local", "S-1-5-21-1111111111-2222222222-3333333333-526"},
		{"Enterprise Key Admins", "CN=Enterprise Key Admins,CN=Users,DC=corp,DC=local", "S-1-5-21-1111111111-2222222222-3333333333-527"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := types.User{
				SAMAccountName: "svc-" + tc.name,
				AdminCount:     true,
				MemberOf:       []string{tc.group},
			}
			data := &audit.DetectorData{
				Users:       []types.User{u},
				ObjectBySID: map[string]*audit.ObjectMeta{tc.sid: {DN: tc.group, SID: tc.sid, EntityType: types.EntityTypeGroup}},
			}

			f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("membership in %q (an Appendix C protected group, resolved by SID suffix) legitimately explains adminCount=1; must not be flagged as orphaned, got Count=%d", tc.name, f.Count)
			}
		})
	}
}

// TestAdminCountOrphaned_HomonymGroupNotProtected is the homonym-group
// case: a group whose CN is literally "Backup Operators" but which lives
// outside CN=Builtin and carries an ordinary domain RID (not -551) grants no
// real SDProp protection. Before the fix (name-based
// helpers.IsInAnyGroup), this membership alone would have "explained"
// adminCount=1; after the fix it must not, and the user is flagged as
// orphaned.
func TestAdminCountOrphaned_HomonymGroupNotProtected(t *testing.T) {
	fakeDN := "CN=Backup Operators,CN=Users,DC=example,DC=com"
	fakeSID := "S-1-5-21-1111111111-2222222222-3333333333-9105" // ordinary domain RID, not -551
	u := types.User{
		SAMAccountName: "homonym-member",
		AdminCount:     true,
		MemberOf:       []string{fakeDN},
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{fakeSID: {DN: fakeDN, SID: fakeSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("membership in a Backup-Operators-named group with an ordinary RID must NOT explain adminCount=1 (false positive fixed); got Count=%d, want 1", f.Count)
	}
}

// TestAdminCountOrphaned_RenamedGroupStillProtected is the
// renamed-group case: the real Backup Operators group (S-1-5-32-551) renamed to
// its French localized display name must still be recognized, because the
// match is by SID suffix, not by English CN.
func TestAdminCountOrphaned_RenamedGroupStillProtected(t *testing.T) {
	localizedDN := "CN=Opérateurs de sauvegarde,CN=Builtin,DC=example,DC=com"
	realSID := "S-1-5-32-551"
	u := types.User{
		SAMAccountName: "localized-member",
		AdminCount:     true,
		MemberOf:       []string{localizedDN},
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{realSID: {DN: localizedDN, SID: realSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("membership in the real Backup Operators group (S-1-5-32-551) under a localized name must still explain adminCount=1; got Count=%d, want 0", f.Count)
	}
}

// TestAdminCountOrphaned_ExactProtectedGroupSet is the table-driven
// exact-set lock: inSet is protectedGroupSIDSuffixes' 13 suffixes, written
// here as a literal (never read from the package var) and cross-checked
// against docs/security-validation/results/privileged-by-sid/VERDICT.md §1.
// universe is the union of RID suffixes used by any of the ten detectors
// that share this package's privgroups SID-suffix resolver (28 suffixes),
// plus two witnesses used by NONE of them: -520 (Group Policy Creator
// Owners) and -547 (Power Users), both confirmed against
// internal/audit/wellknown_sids.go. adminCount alone with an in-set
// membership must NOT be flagged (protected); the same with an out-of-set
// membership must still be flagged (orphaned) - a real prior regression
// class: a similar list silently losing one suffix (e.g. -573) passed the
// full suite unnoticed before this table-driven lock existed.
func TestAdminCountOrphaned_ExactProtectedGroupSet(t *testing.T) {
	inSet := []string{
		"-548", "-544", "-551", "-512", "-516", "-519", "-527", "-526",
		"-550", "-521", "-552", "-518", "-549",
	}
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
			u := types.User{SAMAccountName: "member" + suffix, AdminCount: true, MemberOf: []string{dn}}
			data := &audit.DetectorData{
				Users:       []types.User{u},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("suffix %s is in protectedGroupSIDSuffixes; membership must explain adminCount=1, got Count=%d, want 0", suffix, f.Count)
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
			u := types.User{SAMAccountName: "member" + suffix, AdminCount: true, MemberOf: []string{dn}}
			data := &audit.DetectorData{
				Users:       []types.User{u},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("suffix %s is NOT in protectedGroupSIDSuffixes; membership must not explain adminCount=1, got Count=%d, want 1", suffix, f.Count)
			}
		})
	}
}

func TestAdminCountOrphaned_TrulyOrphanedStillFlagged(t *testing.T) {
	u := types.User{
		SAMAccountName: "former-admin",
		AdminCount:     true,
		MemberOf:       []string{"CN=Marketing,CN=Users,DC=corp,DC=local"},
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("adminCount=1 with only a non-protected group membership must still be flagged, got Count=%d", f.Count)
	}
}

// TestAdminCountOrphaned_DisabledProtectedMemberOfNeverCountedActive is the
// mirror half of the disabled-member-of-a-protected-group case: a DISABLED
// account, adminCount=1, direct memberOf of a protected group (Domain
// Admins, RID -512, literal SID/RID distinct from any code constant) must
// never surface in the ACTIVE key either. The disabled-vs-active partition
// is checked elsewhere without a protected memberOf in the fixture
// (TestAdminCountOrphaned_ActiveDisabledPartition); this fixture combines
// "disabled" with "protected memberOf" so the claim "compté nulle part" is
// backed by an explicit case, not inferred from two separate ones.
//
// Note (see VERDICT.md "Réserves"): for this exact fixture, breaking the
// u.Disabled skip alone does not turn this test red, because the protected
// memberOf independently exempts the account too - the two guards are
// redundant here. Documented, not hidden.
func TestAdminCountOrphaned_DisabledProtectedMemberOfNeverCountedActive(t *testing.T) {
	groupDN := "CN=Domain Admins,CN=Users,DC=corp,DC=local"
	groupSID := "S-1-5-21-4444444444-5555555555-6666666666-512"
	u := types.User{
		SAMAccountName: "disabled-domain-admin-mirror",
		AdminCount:     true,
		Disabled:       true,
		MemberOf:       []string{groupDN},
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("a disabled account with a protected direct memberOf must not be counted in the ACTIVE key, got Count=%d, want 0", f.Count)
	}
}

// TestAdminCountOrphaned_PrimaryGroupIndexedButNotProtectedStillFlagged is
// C2: an active user whose primary group IS present in data.ObjectBySID
// (unlike TestAdminCountOrphaned_PrimaryGroupOrdinaryRIDStillFlagged, which
// leaves ObjectBySID nil and only exercises the meta==nil early return of
// primaryGroupIsProtected) but is an ORDINARY global group, not one of
// protectedGroupSIDSuffixes. The account must still be flagged: presence in
// the index is not the same as membership in protectedGroupDNs.
func TestAdminCountOrphaned_PrimaryGroupIndexedButNotProtectedStillFlagged(t *testing.T) {
	const domainSID = "S-1-5-21-7777777777-8888888888-9999999999"
	const primaryGroupRID = 9310 // ordinary global group, arbitrary RID, not a protected suffix
	groupDN := "CN=Marketing,CN=Users,DC=corp,DC=local"
	groupSID := domainSID + "-" + strconv.Itoa(primaryGroupRID)

	u := types.User{
		SAMAccountName: "primary-group-indexed-not-protected",
		AdminCount:     true,
		PrimaryGroupID: primaryGroupRID,
	}
	data := &audit.DetectorData{
		Users:      []types.User{u},
		DomainInfo: &types.DomainInfo{DomainSID: domainSID},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("a primary group present in the index but not in protectedGroupDNs must not exempt the account, got Count=%d, want 1", f.Count)
	}
}

// TestAdminCountOrphaned_RecommendationLocked is a literal lock on
// Details["recommendation"], typed independently of the source, the same
// idiom as TestAdminCountOrphaned_DescriptionLocked.
func TestAdminCountOrphaned_RecommendationLocked(t *testing.T) {
	const want = "Verify there is no NESTED protected-group membership (direct membership and primary group are already ruled out) before clearing the adminCount flag; only then reset ACLs to allow proper inheritance."

	u := types.User{
		SAMAccountName: "former-admin-recommendation-lock",
		AdminCount:     true,
		MemberOf:       []string{"CN=Marketing,CN=Users,DC=corp,DC=local"},
	}
	data := &audit.DetectorData{Users: []types.User{u}, IncludeDetails: true}

	f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	got, _ := f.Details["recommendation"].(string)
	if got != want {
		t.Fatalf("ADMIN_COUNT_ORPHANED recommendation drifted from the locked text.\ngot:  %s\nwant: %s", got, want)
	}
}
