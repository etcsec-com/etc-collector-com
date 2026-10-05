package other

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestEphemeralAdmins_DetectsShadowPrincipalAcrossPrincipalTypes is a
// synthetic-data proof that EPHEMERAL_ADMINS_PAM's substring heuristic
// actually fires - this detector has never triggered on the lab (a real
// plant would require populating msDS-ShadowPrincipal in a bastion-forest
// PAM deployment, unavailable there).
//
// It also proves the fix for the detector's admitted scope limitation: the
// original code only scanned Users' memberOf. Since a shadow principal
// ([MS-ADSC] msDS-ShadowPrincipal) can represent a user, group, or computer,
// this test gives one of each a memberOf DN referencing a shadow principal
// and expects all three to be counted. Against the pre-fix code (Users
// only), Count would be 1 and the computer/group would be silently missed -
// this test fails there and passes once Computers and Groups are scanned
// too.
func TestEphemeralAdmins_DetectsShadowPrincipalAcrossPrincipalTypes(t *testing.T) {
	const shadowDN = "CN=S-1-5-21-111-222-333-1105,CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=priv,DC=example,DC=com"

	users := []types.User{
		{DN: "CN=alice,DC=priv,DC=example,DC=com", MemberOf: []string{shadowDN}},
		{DN: "CN=dave,DC=priv,DC=example,DC=com", MemberOf: []string{"CN=Regular Group,DC=priv,DC=example,DC=com"}},
	}
	computers := []types.Computer{
		{DN: "CN=JUMP01,DC=priv,DC=example,DC=com", MemberOf: []string{shadowDN}},
	}
	groups := []types.Group{
		{DN: "CN=Tier0Admins,DC=priv,DC=example,DC=com", MemberOf: []string{shadowDN}},
	}

	data := &audit.DetectorData{
		IncludeDetails: true,
		Users:          users,
		Computers:      computers,
		Groups:         groups,
	}

	findings := NewEphemeralAdminsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]

	if f.Count != 3 {
		t.Fatalf("expected Count=3 (one user, one computer, one group), got %d", f.Count)
	}
	if len(f.AffectedEntities) != 3 {
		t.Fatalf("expected 3 affected entities, got %d (%+v)", len(f.AffectedEntities), f.AffectedEntities)
	}

	seen := map[string]bool{}
	for _, ent := range f.AffectedEntities {
		seen[ent.DN] = true
	}
	for _, dn := range []string{users[0].DN, computers[0].DN, groups[0].DN} {
		if !seen[dn] {
			t.Fatalf("expected %q among affected entities, got %+v", dn, f.AffectedEntities)
		}
	}
	if seen[users[1].DN] {
		t.Fatalf("dave has no shadow-principal membership and must not be flagged")
	}

	// The description must not claim a direct read of the shadow principal
	// container - the method is a substring match on memberOf.
	descLower := strings.ToLower(f.Description)
	if !strings.Contains(descLower, "heuristic") && !strings.Contains(descLower, "substring") {
		t.Fatalf("description does not disclose the substring-match method: %q", f.Description)
	}
}

// TestEphemeralAdmins_NoMatchesYieldsZeroCount is the negative case: no
// memberOf value anywhere near "shadow principal" must not raise a finding.
func TestEphemeralAdmins_NoMatchesYieldsZeroCount(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=alice,DC=example,DC=com", MemberOf: []string{"CN=Domain Admins,DC=example,DC=com"}},
		},
		Computers: []types.Computer{
			{DN: "CN=SRV01,DC=example,DC=com", MemberOf: []string{"CN=Servers,DC=example,DC=com"}},
		},
		Groups: []types.Group{
			{DN: "CN=IT,DC=example,DC=com", MemberOf: []string{"CN=Groups,DC=example,DC=com"}},
		},
	}

	findings := NewEphemeralAdminsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0, got %d (%+v)", findings[0].Count, findings[0].AffectedEntities)
	}
}
