package nist

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAC6LeastPrivilege_SpecialPrincipalBlindSpot covers T_127: Server
// Operators and Backup Operators are domain-local Builtin groups, so
// Everyone/Authenticated Users can be a member of either without that
// membership ever appearing in any real user's memberOf (Windows computes it
// at logon time, it never writes a per-user back-link). Confirmed live on
// DC01 (T_125 confrontation): usersInMultiplePrivGroups went from 1 to 27 —
// every enabled account in the domain — once this was fixed. This test
// isolates the mechanism with synthetic data, independent of that live run.
func TestAC6LeastPrivilege_SpecialPrincipalBlindSpot(t *testing.T) {
	const domainDN = "DC=example,DC=com"
	user := types.User{
		SAMAccountName: "svc.one",
		Disabled:       false, // enabled
		MemberOf:       []string{"CN=Account Operators,CN=Builtin," + domainDN},
	}

	tests := []struct {
		name             string
		groups           []types.Group
		wantUsersInMulti int
	}{
		{
			name:             "no group data — one privileged group only, not counted",
			groups:           nil,
			wantUsersInMulti: 0,
		},
		{
			name: "Server Operators open to Authenticated Users — now counted",
			groups: []types.Group{
				{SAMAccountName: "Server Operators", Members: []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals," + domainDN}},
			},
			wantUsersInMulti: 1,
		},
		{
			name: "Backup Operators open to Everyone — now counted",
			groups: []types.Group{
				{SAMAccountName: "Backup Operators", Members: []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals," + domainDN}},
			},
			wantUsersInMulti: 1,
		},
		{
			name: "both open — still counted once per user, not twice",
			groups: []types.Group{
				{SAMAccountName: "Server Operators", Members: []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals," + domainDN}},
				{SAMAccountName: "Backup Operators", Members: []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals," + domainDN}},
			},
			wantUsersInMulti: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Users:  []types.User{user},
				Groups: tt.groups,
			}
			findings := NewAC6LeastPrivilegeDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding wrapper, got %d", len(findings))
			}
			got, _ := findings[0].Details["usersInMultiplePrivGroups"].(int)
			if got != tt.wantUsersInMulti {
				t.Errorf("usersInMultiplePrivGroups = %d, want %d", got, tt.wantUsersInMulti)
			}
		})
	}
}
