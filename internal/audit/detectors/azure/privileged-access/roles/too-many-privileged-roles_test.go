package roles

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// buildAssignments returns n role assignments for the given role ID.
func buildAssignments(roleID string, n int) []types.RoleAssignment {
	out := make([]types.RoleAssignment, n)
	for i := range out {
		out[i] = types.RoleAssignment{RoleID: roleID, PrincipalID: "p"}
	}
	return out
}

func TestThresholdRoles_TableDriven(t *testing.T) {
	cases := []struct {
		name      string
		detector  audit.Detector
		roleID    string
		threshold int
	}{
		{"PRA", NewTooManyPrivilegedRoleAdminsDetector(), types.AzureRolePrivilegedRoleAdmin, 3},
		{"Security", NewTooManySecurityAdminsDetector(), types.AzureRoleSecurityAdmin, 3},
		{"Exchange", NewTooManyExchangeAdminsDetector(), types.AzureRoleExchangeAdmin, 3},
		{"SharePoint", NewTooManySharePointAdminsDetector(), types.AzureRoleSharePointAdmin, 3},
		{"App", NewTooManyAppAdminsDetector(), types.AzureRoleAppAdmin, 5},
	}

	for _, c := range cases {
		t.Run(c.name+"_below_threshold", func(t *testing.T) {
			data := &audit.DetectorData{AzureRoleAssignments: buildAssignments(c.roleID, c.threshold)}
			f := c.detector.Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("%s: expected 0 at threshold, got %d", c.name, f.Count)
			}
		})
		t.Run(c.name+"_above_threshold", func(t *testing.T) {
			data := &audit.DetectorData{AzureRoleAssignments: buildAssignments(c.roleID, c.threshold+1)}
			f := c.detector.Detect(context.Background(), data)[0]
			if f.Count != c.threshold+1 {
				t.Fatalf("%s: expected %d above threshold, got %d", c.name, c.threshold+1, f.Count)
			}
		})
		t.Run(c.name+"_ignores_other_roles", func(t *testing.T) {
			data := &audit.DetectorData{AzureRoleAssignments: buildAssignments("unrelated-role", 10)}
			f := c.detector.Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("%s: expected 0 for unrelated role, got %d", c.name, f.Count)
			}
		})
	}
}
