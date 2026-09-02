package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func daMember(sam string) types.User {
	return types.User{
		SAMAccountName: sam,
		MemberOf:       []string{"CN=Domain Admins,CN=Users,DC=test,DC=local"},
	}
}

func TestR2PrivilegedAccounts_Detect(t *testing.T) {
	cases := []struct {
		name      string
		data      *audit.DetectorData
		wantCount int
	}{
		{
			name: "4 Domain Admins, no SPN -> clean (T_131 live lab baseline)",
			data: &audit.DetectorData{
				Users: []types.User{
					daMember("Administrator"), daMember("admin"), daMember("administrator2"), daMember("backup_admin"),
				},
			},
			wantCount: 0,
		},
		{
			name: "11 Domain Admins -> flagged (>10 threshold)",
			data: &audit.DetectorData{
				Users: func() []types.User {
					var u []types.User
					for i := 0; i < 11; i++ {
						u = append(u, daMember("da_user"))
					}
					return u
				}(),
			},
			wantCount: 1,
		},
		{
			name: "SPN-bearing account in Domain Admins -> flagged (T_131 live-verified on DC01)",
			data: &audit.DetectorData{
				Users: []types.User{
					{
						SAMAccountName:        "backup_admin",
						MemberOf:              []string{"CN=Domain Admins,CN=Users,DC=test,DC=local"},
						ServicePrincipalNames: []string{"t131/kerbtest-r2.test.local"},
					},
				},
			},
			wantCount: 1,
		},
		{
			name: "SPN on a non-DA account -> not flagged",
			data: &audit.DetectorData{
				Users: []types.User{
					{SAMAccountName: "svc_regular", ServicePrincipalNames: []string{"http/web01"}},
				},
			},
			wantCount: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewR2PrivilegedAccountsDetector()
			findings := d.Detect(context.Background(), tc.data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding struct, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Errorf("Count = %d, want %d (details=%+v)", findings[0].Count, tc.wantCount, findings[0].Details)
			}
		})
	}
}
