package security

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AZ_GROUP_ORPHANED - the finding's own self-description must not
// claim "Orphaned" (which reads as the ownerless sense that AZ_GROUP_NO_OWNER
// actually covers) for a check that only ever measures member count, since
// MemberOf is never populated for Azure groups by the collector.
func TestGroupOrphaned_TitleDoesNotClaimOwnership(t *testing.T) {
	d := NewOrphanedGroupsDetector()
	data := &audit.DetectorData{
		Groups: []types.Group{{SAMAccountName: "empty-group"}},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if strings.Contains(findings[0].Title, "Orphaned") {
		t.Fatalf("title must not say Orphaned (reads as ownerless, which is AZ_GROUP_NO_OWNER's territory), got %q", findings[0].Title)
	}
	if !strings.Contains(findings[0].Description, "AZ_GROUP_NO_OWNER") {
		t.Fatalf("description must disambiguate from AZ_GROUP_NO_OWNER, got %q", findings[0].Description)
	}
}

func TestGroupOrphaned_StillFlagsEmptyGroups(t *testing.T) {
	d := NewOrphanedGroupsDetector()
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "empty-group"},
			{SAMAccountName: "populated-group", Members: []string{"user1"}},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected exactly 1 finding with Count=1, got %+v", findings)
	}
}
