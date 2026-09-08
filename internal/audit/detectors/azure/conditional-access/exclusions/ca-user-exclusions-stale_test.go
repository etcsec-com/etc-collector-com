package exclusions

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CA_USER_EXCLUSIONS_STALE - "Stale" implies a time-based check
// (unreviewed for N days), but no exclusion-added timestamp is collected or
// evaluated; the actual logic measures named-user vs group-based exclusion.
// The finding's own self-description must say that, not imply staleness.
func TestUserExclusionsStale_TitleDoesNotClaimStaleness(t *testing.T) {
	d := NewUserExclusionsStaleDetector()
	data := &audit.DetectorData{
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{
				State:        "enabled",
				ExcludeUsers: []string{"user-object-id-1"},
			},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if strings.Contains(findings[0].Title, "Stale") {
		t.Fatalf("title must not claim staleness (no time-based check exists), got %q", findings[0].Title)
	}
	if strings.Contains(findings[0].Description, "how long") == false {
		t.Fatalf("description should clarify duration is not what's measured, got %q", findings[0].Description)
	}
	if findings[0].Count != 1 {
		t.Fatalf("named-user exclusion must still be flagged, got Count=%d", findings[0].Count)
	}
}
