package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestServerOperatorsOnDisabledAccount_DisabledUserFlagged is the baseline
// positive: a disabled direct user member of the real Server Operators
// group (S-1-5-32-549) must be counted here.
func TestServerOperatorsOnDisabledAccount_DisabledUserFlagged(t *testing.T) {
	disabledDN := "CN=Disabled,CN=Users,DC=corp,DC=local"
	group := types.Group{DN: serverOperatorsRealDN, Members: []string{disabledDN}}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
		Users:          []types.User{{DN: disabledDN, SAMAccountName: "disabled", Disabled: true}},
		ObjectBySID:    serverOperatorsSIDIndex(serverOperatorsRealDN),
		IncludeDetails: true,
	}

	f := NewServerOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled real Server Operators user membership)", f.Count)
	}
	if f.AffectedEntities[0].DN != disabledDN {
		t.Fatalf("expected the disabled user %q, got %q", disabledDN, f.AffectedEntities[0].DN)
	}
}

// TestServerOperatorsOnDisabledAccount_DisabledComputerFlagged is the
// computer-side mirror of the baseline positive.
func TestServerOperatorsOnDisabledAccount_DisabledComputerFlagged(t *testing.T) {
	disabledDN := "CN=DISABLED1,CN=Computers,DC=corp,DC=local"
	group := types.Group{DN: serverOperatorsRealDN, Members: []string{disabledDN}}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
		Computers:      []types.Computer{{DN: disabledDN, SAMAccountName: "DISABLED1$", Disabled: true}},
		ObjectBySID:    serverOperatorsSIDIndex(serverOperatorsRealDN),
		IncludeDetails: true,
	}

	f := NewServerOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled real Server Operators computer membership)", f.Count)
	}
	if f.AffectedEntities[0].DN != disabledDN {
		t.Fatalf("expected the disabled computer %q, got %q", disabledDN, f.AffectedEntities[0].DN)
	}
}

// TestServerOperatorsOnDisabledAccount_ActiveMemberNotFlagged is the
// partition guard from this detector's side: an enabled direct member of
// the real Server Operators group must not be counted here - it belongs to
// ServerOperatorsDetector instead. The opposite side is asserted by
// TestServerOperators_DisabledUserExcluded_ActiveIncluded.
func TestServerOperatorsOnDisabledAccount_ActiveMemberNotFlagged(t *testing.T) {
	activeDN := "CN=Active,CN=Users,DC=corp,DC=local"
	group := types.Group{DN: serverOperatorsRealDN, Members: []string{activeDN}}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
		Users:          []types.User{{DN: activeDN, SAMAccountName: "active"}},
		ObjectBySID:    serverOperatorsSIDIndex(serverOperatorsRealDN),
		IncludeDetails: true,
	}

	f := NewServerOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (enabled member must not be counted as a disabled Server Operators member)", f.Count)
	}
}

// TestServerOperatorsOnDisabledAccount_FSPAndNestedGroupNeverFlagged
// confirms this detector only ever reports user/computer kinds: a FSP and a
// nested group carry no UserAccountControl and must never appear here, even
// though they resolve through the exact same ResolveRealMembers call.
func TestServerOperatorsOnDisabledAccount_FSPAndNestedGroupNeverFlagged(t *testing.T) {
	fspDN := "CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=corp,DC=local"
	nestedDN := "CN=IT Support,CN=Users,DC=corp,DC=local"
	group := types.Group{DN: serverOperatorsRealDN, Members: []string{fspDN, nestedDN}}
	nested := types.Group{DN: nestedDN, CN: "IT Support", SAMAccountName: "IT Support"}
	data := &audit.DetectorData{
		Groups:         []types.Group{group, nested},
		ObjectBySID:    serverOperatorsSIDIndex(serverOperatorsRealDN),
		IncludeDetails: true,
	}

	f := NewServerOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (FSP and nested group have no disabled state)", f.Count)
	}
}

// TestServerOperatorsOnDisabledAccount_ExactGroupSet locks the SID this
// detector matches to -549 alone, all fixtures disabled: a neighbor SID
// (-548 Account Operators, -550 Print Operators, -551 Backup Operators)
// carried by a disabled member must not be flagged.
func TestServerOperatorsOnDisabledAccount_ExactGroupSet(t *testing.T) {
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
			memberDN := "CN=Member" + tc.sid + ",CN=Users,DC=corp,DC=local"
			group := types.Group{DN: dn, Members: []string{memberDN}}
			data := &audit.DetectorData{
				Groups:         []types.Group{group},
				Users:          []types.User{{DN: memberDN, SAMAccountName: "member", Disabled: true}},
				ObjectBySID:    map[string]*audit.ObjectMeta{tc.sid: {DN: dn, SID: tc.sid, EntityType: types.EntityTypeGroup}},
				IncludeDetails: true,
			}
			f := NewServerOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
			if f.Count != tc.wantCount {
				t.Fatalf("SID %s: Count = %d, want %d", tc.sid, f.Count, tc.wantCount)
			}
		})
	}
}

// TestServerOperatorsOnDisabledAccount_SeverityIsLow locks this detector's
// severity at Low, distinct from the High of the active-member detector.
func TestServerOperatorsOnDisabledAccount_SeverityIsLow(t *testing.T) {
	disabledDN := "CN=Disabled,CN=Users,DC=corp,DC=local"
	group := types.Group{DN: serverOperatorsRealDN, Members: []string{disabledDN}}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
		Users:          []types.User{{DN: disabledDN, SAMAccountName: "disabled", Disabled: true}},
		ObjectBySID:    serverOperatorsSIDIndex(serverOperatorsRealDN),
		IncludeDetails: true,
	}

	f := NewServerOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityLow {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityLow)
	}
}

// TestServerOperatorsOnDisabledAccount_DescriptionTextLocked locks the
// Detect()-side Description text against silent drift, same rationale as
// TestServerOperators_DescriptionTextLocked.
func TestServerOperatorsOnDisabledAccount_DescriptionTextLocked(t *testing.T) {
	disabledDN := "CN=Disabled,CN=Users,DC=corp,DC=local"
	group := types.Group{DN: serverOperatorsRealDN, Members: []string{disabledDN}}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
		Users:          []types.User{{DN: disabledDN, SAMAccountName: "disabled", Disabled: true}},
		ObjectBySID:    serverOperatorsSIDIndex(serverOperatorsRealDN),
		IncludeDetails: true,
	}

	want := "Disabled users and computers that are direct members of Server Operators cannot authenticate while disabled, so they cannot exercise the privilege. Membership is not removed by this state - it returns to full effect the instant the account is re-enabled. Remediation: remove the account from the group."
	f := NewServerOperatorsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Description != want {
		t.Fatalf("Description = %q, want %q", f.Description, want)
	}
}
