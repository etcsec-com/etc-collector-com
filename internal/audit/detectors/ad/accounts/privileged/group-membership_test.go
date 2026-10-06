package privileged

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestFindGroupBySID_ResolvesViaObjectBySID is the baseline positive: the
// SID maps to a DN in ObjectBySID, and that DN matches a collected group.
func TestFindGroupBySID_ResolvesViaObjectBySID(t *testing.T) {
	dn := "CN=Server Operators,CN=Builtin,DC=corp,DC=local"
	sid := "S-1-5-32-549"
	group := types.Group{DN: dn, CN: "Server Operators"}
	data := &audit.DetectorData{
		Groups:      []types.Group{group},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	got := FindGroupBySID(data, sid)
	if got == nil {
		t.Fatal("expected a group, got nil")
	}
	if got.DN != dn {
		t.Fatalf("DN = %q, want %q", got.DN, dn)
	}
}

// TestFindGroupBySID_LocalizedNameStillMatches confirms the whole point of
// resolving by SID instead of CN/sAMAccountName: a renamed/localized group
// (French display name, e.g. "Opérateurs de serveur") is still found,
// because the match never looks at the name.
func TestFindGroupBySID_LocalizedNameStillMatches(t *testing.T) {
	dn := "CN=Opérateurs de serveur,CN=Builtin,DC=corp,DC=local"
	sid := "S-1-5-32-549"
	group := types.Group{DN: dn, CN: "Opérateurs de serveur"}
	data := &audit.DetectorData{
		Groups:      []types.Group{group},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	got := FindGroupBySID(data, sid)
	if got == nil {
		t.Fatal("expected the localized group to be found by SID, got nil")
	}
}

// TestFindGroupBySID_HomonymNeverMatches is the decoy case in both possible
// slice orders: a group literally named "Server Operators" but carrying an
// ordinary domain RID (not -549, so absent from ObjectBySID under the -549
// key) must never be returned when looking up S-1-5-32-549 - regardless of
// whether it sits before or after the real group in data.Groups.
func TestFindGroupBySID_HomonymNeverMatches(t *testing.T) {
	realDN := "CN=Server Operators,CN=Builtin,DC=corp,DC=local"
	realSID := "S-1-5-32-549"
	decoy := types.Group{DN: "CN=Server Operators,CN=Users,DC=corp,DC=local", CN: "Server Operators"}
	real := types.Group{DN: realDN, CN: "Server Operators"}
	meta := map[string]*audit.ObjectMeta{realSID: {DN: realDN, SID: realSID, EntityType: types.EntityTypeGroup}}

	t.Run("decoy_first", func(t *testing.T) {
		data := &audit.DetectorData{Groups: []types.Group{decoy, real}, ObjectBySID: meta}
		got := FindGroupBySID(data, realSID)
		if got == nil || got.DN != realDN {
			t.Fatalf("expected the real group %q, got %+v", realDN, got)
		}
	})

	t.Run("decoy_second", func(t *testing.T) {
		data := &audit.DetectorData{Groups: []types.Group{real, decoy}, ObjectBySID: meta}
		got := FindGroupBySID(data, realSID)
		if got == nil || got.DN != realDN {
			t.Fatalf("expected the real group %q, got %+v", realDN, got)
		}
	})
}

// TestFindGroupBySID_SIDNotInIndex_ReturnsNil covers a SID never collected
// into ObjectBySID (group not observed, or observed without an ObjectSID) -
// must fail closed, not panic or fall back to name matching.
func TestFindGroupBySID_SIDNotInIndex_ReturnsNil(t *testing.T) {
	data := &audit.DetectorData{
		Groups:      []types.Group{{DN: "CN=Server Operators,CN=Builtin,DC=corp,DC=local", CN: "Server Operators"}},
		ObjectBySID: map[string]*audit.ObjectMeta{},
	}

	if got := FindGroupBySID(data, "S-1-5-32-549"); got != nil {
		t.Fatalf("expected nil when the SID isn't indexed, got %+v", got)
	}
}

// TestFindGroupBySID_DNCaseInsensitive confirms the DN match against
// data.Groups tolerates a case difference between ObjectBySID's DN and the
// collected group's own DN.
func TestFindGroupBySID_DNCaseInsensitive(t *testing.T) {
	sid := "S-1-5-32-549"
	group := types.Group{DN: "cn=server operators,cn=builtin,dc=corp,dc=local", CN: "Server Operators"}
	data := &audit.DetectorData{
		Groups:      []types.Group{group},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: "CN=Server Operators,CN=Builtin,DC=corp,DC=local", SID: sid, EntityType: types.EntityTypeGroup}},
	}

	if got := FindGroupBySID(data, sid); got == nil {
		t.Fatal("expected a case-insensitive DN match, got nil")
	}
}

// TestResolveRealMembers_DisabledPopulatedForUser confirms ResolveRealMembers
// fills ClassifiedMember.Disabled from the user's own Disabled field - the
// field this ticket adds so callers can split active from disabled members
// without re-deriving it themselves.
func TestResolveRealMembers_DisabledPopulatedForUser(t *testing.T) {
	activeDN := "CN=Active,CN=Users,DC=corp,DC=local"
	disabledDN := "CN=Disabled,CN=Users,DC=corp,DC=local"
	group := types.Group{
		DN:      "CN=Server Operators,CN=Builtin,DC=corp,DC=local",
		Members: []string{activeDN, disabledDN},
	}
	data := &audit.DetectorData{
		Groups: []types.Group{group},
		Users: []types.User{
			{DN: activeDN, SAMAccountName: "active", Disabled: false},
			{DN: disabledDN, SAMAccountName: "disabled", Disabled: true},
		},
	}

	members := ResolveRealMembers(data, &data.Groups[0])
	if len(members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(members))
	}
	byDN := map[string]ClassifiedMember{}
	for _, m := range members {
		byDN[m.Entity.DN] = m
	}
	if byDN[activeDN].Disabled {
		t.Fatalf("active user %q: Disabled = true, want false", activeDN)
	}
	if !byDN[disabledDN].Disabled {
		t.Fatalf("disabled user %q: Disabled = false, want true", disabledDN)
	}
}

// TestResolveRealMembers_DisabledPopulatedForComputer is the computer-side
// mirror of TestResolveRealMembers_DisabledPopulatedForUser.
func TestResolveRealMembers_DisabledPopulatedForComputer(t *testing.T) {
	activeDN := "CN=ACTIVE1,CN=Computers,DC=corp,DC=local"
	disabledDN := "CN=DISABLED1,CN=Computers,DC=corp,DC=local"
	group := types.Group{
		DN:      "CN=Server Operators,CN=Builtin,DC=corp,DC=local",
		Members: []string{activeDN, disabledDN},
	}
	data := &audit.DetectorData{
		Groups: []types.Group{group},
		Computers: []types.Computer{
			{DN: activeDN, SAMAccountName: "ACTIVE1$", Disabled: false},
			{DN: disabledDN, SAMAccountName: "DISABLED1$", Disabled: true},
		},
	}

	members := ResolveRealMembers(data, &data.Groups[0])
	byDN := map[string]ClassifiedMember{}
	for _, m := range members {
		byDN[m.Entity.DN] = m
	}
	if byDN[activeDN].Disabled {
		t.Fatalf("active computer %q: Disabled = true, want false", activeDN)
	}
	if !byDN[disabledDN].Disabled {
		t.Fatalf("disabled computer %q: Disabled = false, want true", disabledDN)
	}
}

// TestResolveRealMembers_DisabledZeroValueForGroupAndFSP confirms Disabled
// stays at its false zero value for member kinds that carry no
// UserAccountControl (nested group, foreignSecurityPrincipal) - it must
// never be misread as "active" vs "n/a".
func TestResolveRealMembers_DisabledZeroValueForGroupAndFSP(t *testing.T) {
	nestedDN := "CN=IT Support,CN=Users,DC=corp,DC=local"
	fspDN := "CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=corp,DC=local"
	group := types.Group{
		DN:      "CN=Server Operators,CN=Builtin,DC=corp,DC=local",
		Members: []string{nestedDN, fspDN},
	}
	data := &audit.DetectorData{
		Groups: []types.Group{group, {DN: nestedDN, CN: "IT Support", SAMAccountName: "IT Support"}},
	}

	members := ResolveRealMembers(data, &data.Groups[0])
	for _, m := range members {
		if m.Kind != MemberKindGroup && m.Kind != MemberKindForeignSecurityPrincipal {
			continue
		}
		if m.Disabled {
			t.Fatalf("kind %q: Disabled = true, want false (zero value, no UserAccountControl)", m.Kind)
		}
	}
}
