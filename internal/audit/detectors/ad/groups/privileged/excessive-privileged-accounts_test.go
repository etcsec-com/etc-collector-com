package privileged

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestExcessivePrivilegedAccounts_EntityOrderIsDeterministic covers
// T_046/B_048: privilegedUsers is a map keyed by DN, so ranging it directly
// to build the affected slice would give a randomized order per process.
// With more than 10 Domain Admins (crossing the "excessive" threshold), an
// unsorted range would very rarely land in DN order by chance across
// repeated calls — asserting the exact expected order pins the sort.
func TestExcessivePrivilegedAccounts_EntityOrderIsDeterministic(t *testing.T) {
	const domainDN = "DC=example,DC=com"
	// 11 accounts > the 10-Domain-Admins threshold. Reverse-alphabetical
	// creation order so a stable-but-unsorted implementation would fail.
	var users []types.User
	var want []string
	for i := 11; i >= 1; i-- {
		dn := fmt.Sprintf("CN=admin-%02d,CN=Users,%s", i, domainDN)
		users = append(users, types.User{
			DN:       dn,
			MemberOf: []string{"CN=Domain Admins,CN=Users," + domainDN},
		})
	}
	for i := 1; i <= 11; i++ {
		want = append(want, fmt.Sprintf("CN=admin-%02d,CN=Users,%s", i, domainDN))
	}

	data := &audit.DetectorData{IncludeDetails: true, Users: users}

	for i := 0; i < 5; i++ {
		findings := NewExcessivePrivilegedAccountsDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("run %d: expected exactly 1 finding, got %d", i, len(findings))
		}
		if findings[0].Count == 0 {
			t.Fatalf("run %d: 11 Domain Admins must cross the excessive threshold, count=0", i)
		}
		ents := findings[0].AffectedEntities
		if len(ents) != len(want) {
			t.Fatalf("run %d: expected %d entities, got %d (%v)", i, len(want), len(ents), ents)
		}
		for j, ent := range ents {
			if ent.DN != want[j] {
				t.Fatalf("run %d: entity order not deterministic — position %d = %q, want %q", i, j, ent.DN, want[j])
			}
		}
	}
}

func privilegedUser(dn, sam, groupCN string) types.User {
	return types.User{
		DN:             dn,
		SAMAccountName: sam,
		MemberOf:       []string{"CN=" + groupCN + ",CN=Users,DC=test,DC=local"},
	}
}

// TestExcessivePrivilegedAccounts_Detect covers T_131: live-verified against
// this lab's actual baseline (4 Domain Admins, all privileged groups small —
// never_observed in CHECKS.yml, confirmed unchanged in this session) plus
// the two threshold branches by direct code reading (not provoked live: both
// require mass privileged-group membership changes, out of mandate without
// an explicit go-ahead — see docs/security-validation/results/t131-manual/).
func TestExcessivePrivilegedAccounts_Detect(t *testing.T) {
	cases := []struct {
		name         string
		data         *audit.DetectorData
		wantExcess   bool
		wantSeverity types.Severity
	}{
		{
			name: "4 Domain Admins, small privileged groups -> clean (T_131 live lab baseline)",
			data: &audit.DetectorData{
				Users: []types.User{
					privilegedUser("CN=a", "Administrator", "Domain Admins"),
					privilegedUser("CN=b", "admin", "Domain Admins"),
					privilegedUser("CN=c", "administrator2", "Domain Admins"),
					privilegedUser("CN=d", "backup_admin", "Domain Admins"),
				},
			},
			wantExcess:   false,
			wantSeverity: types.SeverityLow,
		},
		{
			name: "11 Domain Admins -> excessive",
			data: &audit.DetectorData{
				Users: func() []types.User {
					var u []types.User
					for i := 0; i < 11; i++ {
						u = append(u, privilegedUser("CN=u"+strconv.Itoa(i), "da_user", "Domain Admins"))
					}
					return u
				}(),
			},
			wantExcess:   true,
			wantSeverity: types.SeverityMedium,
		},
		{
			name: "51 total privileged across groups (each <=10) -> excessive via total threshold",
			data: &audit.DetectorData{
				Users: func() []types.User {
					groups := []string{"Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Backup Operators"}
					var u []types.User
					n := 0
					for _, g := range groups {
						for i := 0; i < 9 && n < 51; i++ {
							u = append(u, privilegedUser("CN=u"+strconv.Itoa(n), "user", g))
							n++
						}
					}
					return u
				}(),
			},
			wantExcess:   true,
			wantSeverity: types.SeverityMedium,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewExcessivePrivilegedAccountsDetector()
			findings := d.Detect(context.Background(), tc.data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding struct, got %d", len(findings))
			}
			f := findings[0]
			gotExcess := f.Count > 0
			if gotExcess != tc.wantExcess {
				t.Errorf("excessive = %v, want %v (count=%d, details=%+v)", gotExcess, tc.wantExcess, f.Count, f.Details)
			}
			if f.Severity != tc.wantSeverity {
				t.Errorf("Severity = %s, want %s", f.Severity, tc.wantSeverity)
			}
		})
	}
}
