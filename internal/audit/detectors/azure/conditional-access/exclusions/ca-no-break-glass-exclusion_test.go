package exclusions

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CA_NO_BREAK_GLASS_EXCLUSION - before the fix, only ExcludeUsers was
// checked, so a policy that targets All users but excludes its break-glass
// account through a group (ExcludeGroups) - a common, Microsoft-documented
// pattern - was wrongly flagged as having no break-glass exclusion at all.
func TestNoBreakGlassExclusion_GroupExclusionCounts(t *testing.T) {
	d := NewNoBreakGlassExclusionDetector()
	data := &audit.DetectorData{
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{
				State:         "enabled",
				IncludeUsers:  []string{"All"},
				ExcludeUsers:  nil,
				ExcludeGroups: []string{"break-glass-group-id"},
			},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("a group-based break-glass exclusion must not be flagged as missing, got Count=%d", findings[0].Count)
	}
}

// A policy targeting All users with no exclusion of any kind must still be
// flagged - the fix must not silence real detections.
func TestNoBreakGlassExclusion_StillFlagsNoExclusionAtAll(t *testing.T) {
	d := NewNoBreakGlassExclusionDetector()
	data := &audit.DetectorData{
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{
				State:        "enabled",
				IncludeUsers: []string{"All"},
			},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected exactly 1 finding with Count=1, got %+v", findings)
	}
}
