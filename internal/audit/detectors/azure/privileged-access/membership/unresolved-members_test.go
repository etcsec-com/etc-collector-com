package membership

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestUnresolved_AllResolved(t *testing.T) {
	d := NewUnresolvedPrivilegedMembersDetector()
	data := &audit.DetectorData{
		AzureRoleAssignments: []types.RoleAssignment{
			{RoleID: types.AzureRoleGlobalAdmin, PrincipalID: "p1", PrincipalName: "Alice", UserPrincipalName: "alice@tenant"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0, got %d", f.Count)
	}
}

func TestUnresolved_UnresolvedGlobalAdmin(t *testing.T) {
	d := NewUnresolvedPrivilegedMembersDetector()
	data := &audit.DetectorData{
		AzureRoleAssignments: []types.RoleAssignment{
			{RoleID: types.AzureRoleGlobalAdmin, PrincipalID: "p1" /* no name */},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1, got %d", f.Count)
	}
	if f.Severity != types.SeverityHigh {
		t.Fatalf("expected high, got %s", f.Severity)
	}
}

func TestUnresolved_NonPrivilegedRoleIgnored(t *testing.T) {
	d := NewUnresolvedPrivilegedMembersDetector()
	data := &audit.DetectorData{
		AzureRoleAssignments: []types.RoleAssignment{
			{RoleID: "not-a-priv-role", PrincipalID: "p1"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for non-privileged role, got %d", f.Count)
	}
}

func TestUnresolved_MailOnlyResolutionCounts(t *testing.T) {
	d := NewUnresolvedPrivilegedMembersDetector()
	data := &audit.DetectorData{
		AzureRoleAssignments: []types.RoleAssignment{
			{RoleID: types.AzureRoleGlobalAdmin, PrincipalID: "p1", Mail: "alice@tenant"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 (mail alone is resolution), got %d", f.Count)
	}
}

func TestUnresolved_MultipleMixed(t *testing.T) {
	d := NewUnresolvedPrivilegedMembersDetector()
	data := &audit.DetectorData{
		AzureRoleAssignments: []types.RoleAssignment{
			{RoleID: types.AzureRoleGlobalAdmin, PrincipalID: "ok", PrincipalName: "A"},
			{RoleID: types.AzureRoleSecurityAdmin, PrincipalID: "bad1"},
			{RoleID: types.AzureRoleExchangeAdmin, PrincipalID: "bad2"},
			{RoleID: "reader", PrincipalID: "ignored"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 2 {
		t.Fatalf("expected 2 unresolved, got %d", f.Count)
	}
}
