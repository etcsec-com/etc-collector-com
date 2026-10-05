package serviceaccounts

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const privilegedGroupDN = "CN=Admins du domaine,CN=Users,DC=contoso,DC=com"

// TestPrivileged_LocalizedGroupNameFlagged covers the well-known-SID fix:
// the old code matched "CN=Domain Admins" as an English literal substring,
// so a domain with a localized or renamed Domain Admins group (still SID
// ...-512) was never detected. Resolving via the group's ObjectSID fixes
// this regardless of display name/locale.
func TestPrivileged_LocalizedGroupNameFlagged(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Groups: []types.Group{
			{DN: privilegedGroupDN, SAMAccountName: "Admins du domaine", ObjectSID: "S-1-5-21-1-2-3-512"},
		},
		Users: []types.User{
			{
				SAMAccountName:        "svc-backup",
				ServicePrincipalNames: []string{"HOST/svc-backup"},
				MemberOf:              []string{privilegedGroupDN},
			},
		},
	}

	findings := NewPrivilegedDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: localized Domain Admins (SID ...-512) must still be caught", findings[0].Count)
	}
}

// TestPrivileged_NonPrivilegedGroupNotFlagged guards against over-matching:
// a service account in an ordinary group must not fire.
func TestPrivileged_NonPrivilegedGroupNotFlagged(t *testing.T) {
	dn := "CN=Backup Job Runners,CN=Users,DC=contoso,DC=com"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DN: dn, SAMAccountName: "Backup Job Runners", ObjectSID: "S-1-5-21-1-2-3-1500"},
		},
		Users: []types.User{
			{SAMAccountName: "svc-backup", ServicePrincipalNames: []string{"HOST/svc-backup"}, MemberOf: []string{dn}},
		},
	}

	findings := NewPrivilegedDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: an ordinary group is not privileged", findings[0].Count)
	}
}
