package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Backup Operators on the lab DC had S-1-1-0 (Everyone) as its only
// member. The old detector scanned data.Users[].MemberOf and stayed silent,
// since an FSP is never a User - a measured false negative.
func TestBackupOperators_ForeignSecurityPrincipalMember_Detected(t *testing.T) {
	group := types.Group{
		DN: "CN=Backup Operators,CN=Builtin,DC=corp,DC=local",
		CN: "Backup Operators",
		Members: []string{
			"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=corp,DC=local",
		},
	}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
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
		DN:      "CN=Backup Operators,CN=Builtin,DC=corp,DC=local",
		CN:      "Backup Operators",
		Members: []string{computer.DN},
	}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
		Computers:      []types.Computer{computer},
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
		DN: "CN=Backup Operators,CN=Builtin,DC=corp,DC=local",
		CN: "Backup Operators",
	}
	data := &audit.DetectorData{
		Groups:         []types.Group{group},
		IncludeDetails: true,
	}

	findings := NewBackupOperatorsDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 for empty group, got %d", findings[0].Count)
	}
}
