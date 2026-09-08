package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Server Operators on the lab DC had S-1-5-11 (Authenticated Users)
// as its only member. The old detector scanned data.Users[].MemberOf, found
// no user whose MemberOf mentioned "CN=Server Operators" (an FSP isn't a
// User), and stayed silent - a measured false negative, not theoretical.
func TestServerOperators_ForeignSecurityPrincipalMember_Detected(t *testing.T) {
	group := types.Group{
		DN: "CN=Server Operators,CN=Builtin,DC=corp,DC=local",
		CN: "Server Operators",
		Members: []string{
			"CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=corp,DC=local",
		},
	}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
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
		DN:      "CN=Server Operators,CN=Builtin,DC=corp,DC=local",
		CN:      "Server Operators",
		Members: []string{nested.DN},
	}
	data := &audit.DetectorData{
		Groups:         []types.Group{group, nested},
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
		DN: "CN=Server Operators,CN=Builtin,DC=corp,DC=local",
		CN: "Server Operators",
	}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
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
