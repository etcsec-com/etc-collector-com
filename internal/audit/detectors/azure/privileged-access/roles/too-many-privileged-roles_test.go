package roles

import (
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// buildAssignments returns n role assignments for the given role ID. Shared
// by the too-many-*-admins_test.go files in this package.
func buildAssignments(roleID string, n int) []types.RoleAssignment {
	out := make([]types.RoleAssignment, n)
	for i := range out {
		out[i] = types.RoleAssignment{RoleID: roleID, PrincipalID: "p"}
	}
	return out
}
