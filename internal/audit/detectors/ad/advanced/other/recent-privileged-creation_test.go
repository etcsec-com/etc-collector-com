package other

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestRecentPrivilegedCreation_PrefixedGroupNameNotFlagged pins the fix for
// the substring-matching bug: helpers.IsInAnyGroup matches "cn=domain
// admins" as a raw substring, so a user whose only group is "Domain
// AdminsX" (a distinct, non-privileged group that merely starts with the
// same name) used to be flagged as a recently created privileged account.
// This must not fire.
func TestRecentPrivilegedCreation_PrefixedGroupNameNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	d := NewRecentPrivilegedCreationDetector()
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				SAMAccountName: "newhire",
				Created:        now.AddDate(0, 0, -2),
				MemberOf:       []string{"CN=Domain AdminsX,OU=Groups,DC=contoso,DC=com"},
			},
		},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: \"Domain AdminsX\" is not \"Domain Admins\"", findings[0].Count)
	}
}

// TestRecentPrivilegedCreation_ExactGroupNameFlagged pins the positive
// case: an account created 2 days ago and a direct member of the real
// "Domain Admins" group must still fire.
func TestRecentPrivilegedCreation_ExactGroupNameFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	d := NewRecentPrivilegedCreationDetector()
	data := &audit.DetectorData{
		Now:            now,
		IncludeDetails: true,
		Users: []types.User{
			{
				SAMAccountName: "newadmin",
				Created:        now.AddDate(0, 0, -2),
				MemberOf:       []string{"CN=Domain Admins,CN=Users,DC=contoso,DC=com"},
			},
		},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: direct member of the real Domain Admins group", findings[0].Count)
	}
}
