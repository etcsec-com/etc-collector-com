package membership

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AZ_GROUP_DYNAMIC_RULE_BROAD - the detector's name and description
// promise an analysis of dynamic membership rules, but before the fix it
// never checked AzureGroupTypes at all: any group (dynamic or plain static
// assigned-membership) with >100 members was flagged. A large static group
// is not a broad dynamic rule.
func TestDynamicRuleBroad_IgnoresStaticGroups(t *testing.T) {
	d := NewDynamicRuleBroadDetector()
	members := make([]string, 150)
	for i := range members {
		members[i] = "user" + string(rune(i))
	}
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				SAMAccountName: "big-static-group",
				Members:        members,
				// AzureGroupTypes intentionally left empty/nil: not dynamic.
			},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("a large static group must not be flagged as a broad dynamic rule, got Count=%d", findings[0].Count)
	}
}

// A genuinely dynamic group with a large resolved membership must still be
// flagged - the fix must not silence real detections.
func TestDynamicRuleBroad_FlagsLargeDynamicGroup(t *testing.T) {
	d := NewDynamicRuleBroadDetector()
	members := make([]string, 150)
	for i := range members {
		members[i] = "user" + string(rune(i))
	}
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				SAMAccountName:  "big-dynamic-group",
				Members:         members,
				AzureGroupTypes: []string{"DynamicMembership"},
			},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected the large dynamic group to be flagged, got Count=%d", findings[0].Count)
	}
}
