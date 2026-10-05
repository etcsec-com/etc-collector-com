package anssi

import (
	"context"
	"strings"
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
			name: "4 Domain Admins, no SPN -> clean ( live lab baseline)",
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
			name: "SPN-bearing account in Domain Admins -> flagged ( live-verified on DC01)",
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

// the ">10 Domain Admins" threshold was previously presented as an
// ANSSI PA-099 requirement. It's INTROUVABLE in the published PA-099 text
// (verified against the full v1.0 PDF, 02/10/2023): no recommendation
// specifies a numeric ceiling on Domain Admins membership. The finding must
// no longer claim ANSSI mandates this specific number.
func TestR2PrivilegedAccounts_DoesNotClaimANSSIMandatesTheHeadcount(t *testing.T) {
	data := &audit.DetectorData{
		Users: func() []types.User {
			var u []types.User
			for i := 0; i < 11; i++ {
				u = append(u, daMember("da_user"))
			}
			return u
		}(),
	}
	d := NewR2PrivilegedAccountsDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count == 0 {
		t.Fatalf("expected a flagged finding, got %+v", findings)
	}
	desc := findings[0].Description
	if strings.Contains(desc, "ANSSI R2 recommendations") || strings.Contains(strings.ToLower(desc), "anssi recommends") {
		t.Errorf("description still attributes the headcount threshold to ANSSI: %q", desc)
	}
	if !strings.Contains(desc, "product benchmark") {
		t.Errorf("description should honestly present the headcount as a product benchmark, got %q", desc)
	}
}
