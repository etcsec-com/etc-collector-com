package roles

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestGroupAssignedAdmin_DetectsRolesBeyondTheFourTracked covers the source
// review finding: the detector reused the shared privilegedRoleIDs (Global
// Admin, Security Admin, Privileged Role Admin, User Admin only), so a group
// holding Exchange Administrator, SharePoint Administrator, Cloud Application
// Administrator, Application Administrator, or Conditional Access
// Administrator went undetected even though the title "Admin Role Assigned
// to Group" promises coverage of admin roles generally.
func TestGroupAssignedAdmin_DetectsRolesBeyondTheFourTracked(t *testing.T) {
	cases := []struct {
		name   string
		roleID string
	}{
		{"ExchangeAdmin", types.AzureRoleExchangeAdmin},
		{"SharePointAdmin", types.AzureRoleSharePointAdmin},
		{"CloudAppAdmin", types.AzureRoleCloudAppAdmin},
		{"AppAdmin", types.AzureRoleAppAdmin},
		{"ConditionalAccessAdmin", types.AzureRoleConditionalAccessAdmin},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := NewGroupAssignedAdminDetector()
			data := &audit.DetectorData{
				AzureRoleAssignments: []types.RoleAssignment{
					{PrincipalType: "Group", RoleID: c.roleID, PrincipalID: "g1"},
				},
			}
			f := d.Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("%s: expected 1 group assignment detected, got %d", c.name, f.Count)
			}
		})
	}
}

func TestGroupAssignedAdmin_IgnoresUserPrincipal(t *testing.T) {
	d := NewGroupAssignedAdminDetector()
	data := &audit.DetectorData{
		AzureRoleAssignments: []types.RoleAssignment{
			{PrincipalType: "User", RoleID: types.AzureRoleExchangeAdmin, PrincipalID: "u1"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for a user (not group) principal, got %d", f.Count)
	}
}
