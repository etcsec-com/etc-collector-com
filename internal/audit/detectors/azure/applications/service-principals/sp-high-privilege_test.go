package serviceprincipals

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestSPHighPrivilege_CoversGraphPrivilegedRoles reproduces the coverage
// gap against Microsoft Graph's own roleDefinition.isPrivileged flag: the
// hardcoded set only covered 4 of the roles Graph marks privileged. Before
// the fix, a service principal holding only User Administrator (isPrivileged
// = true per Microsoft Entra's built-in roles reference) wrongly passed.
// Exchange Administrator - an "Administrator" role that Graph does NOT mark
// privileged - must keep being excluded, so this fix doesn't overreach.
func TestSPHighPrivilege_CoversGraphPrivilegedRoles(t *testing.T) {
	spUserAdmin := types.ServicePrincipal{ID: "11111111-1111-1111-1111-111111111111", DisplayName: "user-admin-sp"}
	spGlobalAdmin := types.ServicePrincipal{ID: "22222222-2222-2222-2222-222222222222", DisplayName: "global-admin-sp"}
	spExchangeAdmin := types.ServicePrincipal{ID: "33333333-3333-3333-3333-333333333333", DisplayName: "exchange-admin-sp"}

	d := NewSPHighPrivilegeDetector()
	data := &audit.DetectorData{
		AzureServicePrincipals: []types.ServicePrincipal{spUserAdmin, spGlobalAdmin, spExchangeAdmin},
		AzureRoleAssignments: []types.RoleAssignment{
			{PrincipalID: spUserAdmin.ID, PrincipalType: "ServicePrincipal", RoleID: types.AzureRoleUserAdmin},
			{PrincipalID: spGlobalAdmin.ID, PrincipalType: "ServicePrincipal", RoleID: types.AzureRoleGlobalAdmin},
			{PrincipalID: spExchangeAdmin.ID, PrincipalType: "ServicePrincipal", RoleID: types.AzureRoleExchangeAdmin},
		},
		IncludeDetails: true,
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 2 {
		t.Fatalf("expected 2 SPs flagged (User Admin + Global Admin), got %d", f.Count)
	}

	flagged := map[string]bool{}
	for _, e := range f.AffectedEntities {
		flagged[e.DisplayName] = true
	}
	if !flagged["user-admin-sp"] {
		t.Error("SP with User Administrator (Graph isPrivileged=true) should now be flagged (previously wrongly passed)")
	}
	if !flagged["global-admin-sp"] {
		t.Error("SP with Global Administrator must still be flagged")
	}
	if flagged["exchange-admin-sp"] {
		t.Error("SP with Exchange Administrator must not be flagged: Graph does not mark this role isPrivileged")
	}
}
