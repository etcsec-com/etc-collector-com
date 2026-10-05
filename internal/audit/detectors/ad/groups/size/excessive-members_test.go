package size

import (
	"context"
	"fmt"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func groupWithMembers(dn string, memberCount int) types.Group {
	members := make([]string, memberCount)
	for i := 0; i < memberCount; i++ {
		members[i] = fmt.Sprintf("CN=plantuser%03d,DC=test,DC=local", i)
	}
	return types.Group{
		DN:             dn,
		SAMAccountName: dn,
		Member:         members,
	}
}

// TestExcessiveMembers_Detect: literal-count fixtures, deliberately NOT
// reusing the detector's excessiveThreshold constant anywhere in the
// expectations - a test that builds AND compares with the same constant can
// never catch a drift of that constant. Each case maps directly to a
// lab-proof witness value (100/101/50 members) plus a mid-range value (60)
// that a weaker threshold would wrongly flag.
func TestExcessiveMembers_Detect(t *testing.T) {
	cases := []struct {
		name      string
		groups    []types.Group
		wantCount int
	}{
		{
			name:      "exactly 100 members does not fire (strict threshold, kills M1 >=)",
			groups:    []types.Group{groupWithMembers("CN=g100,DC=test,DC=local", 100)},
			wantCount: 0,
		},
		{
			name:      "101 members fires",
			groups:    []types.Group{groupWithMembers("CN=g101,DC=test,DC=local", 101)},
			wantCount: 1,
		},
		{
			name:      "60 members does not fire (kills M2 threshold=50)",
			groups:    []types.Group{groupWithMembers("CN=g60,DC=test,DC=local", 60)},
			wantCount: 0,
		},
		{
			name:      "0 members does not fire",
			groups:    []types.Group{groupWithMembers("CN=g0,DC=test,DC=local", 0)},
			wantCount: 0,
		},
		{
			name: "mixed set: only the group above threshold is counted (kills M3 unconditional append)",
			groups: []types.Group{
				groupWithMembers("CN=g101b,DC=test,DC=local", 101),
				groupWithMembers("CN=g100b,DC=test,DC=local", 100),
				groupWithMembers("CN=g50b,DC=test,DC=local", 50),
			},
			wantCount: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{IncludeDetails: true, Groups: tc.groups}
			findings := NewExcessiveMembersDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding struct, got %d", len(findings))
			}
			f := findings[0]
			if f.Count != tc.wantCount {
				t.Errorf("Count = %d, want %d", f.Count, tc.wantCount)
			}
			if f.Type != "GROUP_EXCESSIVE_MEMBERS" {
				t.Errorf("Type = %q, want GROUP_EXCESSIVE_MEMBERS", f.Type)
			}
			if f.Severity != types.SeverityMedium {
				t.Errorf("Severity = %s, want medium", f.Severity)
			}
		})
	}
}

// TestExcessiveMembers_TopFiveSortedDescending covers the largestGroups cap
// (i < 5) and the descending sort - 7 groups above threshold, distinct member
// counts so order is unambiguous, only the top 5 by member count must appear.
func TestExcessiveMembers_TopFiveSortedDescending(t *testing.T) {
	var groups []types.Group
	// Member counts 101..107, intentionally inserted out of order so an
	// implementation that forgot to sort would fail.
	counts := []int{104, 101, 107, 103, 105, 102, 106}
	for i, c := range counts {
		groups = append(groups, groupWithMembers(fmt.Sprintf("CN=g%d,DC=test,DC=local", i), c))
	}

	data := &audit.DetectorData{IncludeDetails: true, Groups: groups}
	findings := NewExcessiveMembersDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding struct, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 7 {
		t.Fatalf("expected all 7 groups above threshold to be counted, got %d", f.Count)
	}

	largest, ok := f.Details["largestGroups"].([]map[string]interface{})
	if !ok {
		t.Fatalf("Details[\"largestGroups\"] missing or wrong type: %+v", f.Details["largestGroups"])
	}
	if len(largest) != 5 {
		t.Fatalf("expected top 5 entries, got %d", len(largest))
	}
	wantOrder := []int{107, 106, 105, 104, 103}
	for i, want := range wantOrder {
		got, _ := largest[i]["memberCount"].(int)
		if got != want {
			t.Errorf("largestGroups[%d].memberCount = %d, want %d (order: %v)", i, got, want, largest)
		}
	}
}

// TestExcessiveMembers_NameFallsBackToDistinguishedName covers the
// SAMAccountName-empty branch (line 60-62 of excessive-members.go): when a
// group carries no sAMAccountName, largestGroups must still name it, via
// DistinguishedName.
func TestExcessiveMembers_NameFallsBackToDistinguishedName(t *testing.T) {
	g := types.Group{
		DN:                "CN=no-sam,DC=test,DC=local",
		DistinguishedName: "CN=no-sam,DC=test,DC=local",
		SAMAccountName:    "",
	}
	members := make([]string, 101)
	for i := range members {
		members[i] = fmt.Sprintf("CN=plantuser%03d,DC=test,DC=local", i)
	}
	g.Member = members

	data := &audit.DetectorData{IncludeDetails: true, Groups: []types.Group{g}}
	findings := NewExcessiveMembersDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding struct, got %d", len(findings))
	}
	largest, ok := findings[0].Details["largestGroups"].([]map[string]interface{})
	if !ok || len(largest) != 1 {
		t.Fatalf("expected exactly 1 largestGroups entry, got %+v", findings[0].Details["largestGroups"])
	}
	if got := largest[0]["name"]; got != "CN=no-sam,DC=test,DC=local" {
		t.Errorf("name = %v, want fallback to DistinguishedName", got)
	}
}
