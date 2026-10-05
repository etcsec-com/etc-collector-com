package patterns

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestPrimaryGroupIdSpoofing covers the ecart fix: the detector used to
// flag ANY primaryGroupID != 513, with no allowance for Microsoft's own
// factory-default non-513 assignments (the built-in Guest account, RID
// 514/Domain Guests, being the only such case actually observed firing on
// the lab). See the isKnownLegitimateNonStandardPrimaryGroup doc comment
// for sourcing.
func TestPrimaryGroupIdSpoofing(t *testing.T) {
	cases := []struct {
		name      string
		user      types.User
		wantCount int
	}{
		{
			name: "built-in Guest (RID 501) with primaryGroupID 514 (Domain Guests) does not fire",
			user: types.User{
				SAMAccountName: "Guest",
				ObjectSID:      "S-1-5-21-1004336348-1177238915-682003330-501",
				PrimaryGroupID: 514,
			},
			wantCount: 0,
		},
		{
			name: "gMSA with primaryGroupID 515 (Domain Computers) does not fire",
			user: types.User{
				SAMAccountName: "svc-backup$",
				ObjectSID:      "S-1-5-21-1004336348-1177238915-682003330-1112",
				PrimaryGroupID: 515,
				IsGMSA:         true,
			},
			wantCount: 0,
		},
		{
			name: "ordinary user with primaryGroupID 513 (standard) does not fire",
			user: types.User{
				SAMAccountName: "jdupont",
				ObjectSID:      "S-1-5-21-1004336348-1177238915-682003330-1105",
				PrimaryGroupID: 513,
			},
			wantCount: 0,
		},
		{
			name: "primaryGroupID 0 (unset/unreadable) does not fire",
			user: types.User{
				SAMAccountName: "unreadable",
				PrimaryGroupID: 0,
			},
			wantCount: 0,
		},
		{
			name: "non-Guest account with primaryGroupID 514 (Domain Guests) still fires - RID doesn't match Guest",
			user: types.User{
				SAMAccountName: "notguest",
				ObjectSID:      "S-1-5-21-1004336348-1177238915-682003330-9999",
				PrimaryGroupID: 514,
			},
			wantCount: 1,
		},
		{
			name: "ordinary user account with primaryGroupID 512 (Domain Admins) but not an explicit member - classic hide-membership spoofing - fires",
			user: types.User{
				SAMAccountName: "attacker",
				ObjectSID:      "S-1-5-21-1004336348-1177238915-682003330-1150",
				PrimaryGroupID: 512,
				MemberOf:       []string{"CN=Marketing,CN=Users,DC=corp,DC=local"},
			},
			wantCount: 1,
		},
		{
			name: "krbtgt with non-standard primaryGroupID still fires - no legitimate default exception exists",
			user: types.User{
				SAMAccountName: "krbtgt",
				ObjectSID:      "S-1-5-21-1004336348-1177238915-682003330-502",
				PrimaryGroupID: 512,
			},
			wantCount: 1,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Users:          []types.User{c.user},
				IncludeDetails: true,
			}
			findings := NewPrimaryGroupIdSpoofingDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding wrapper, got %d", len(findings))
			}
			if findings[0].Count != c.wantCount {
				t.Fatalf("Count = %d, want %d", findings[0].Count, c.wantCount)
			}
		})
	}
}
