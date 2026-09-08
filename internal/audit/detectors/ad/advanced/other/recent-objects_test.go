package other

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestRecentObjectsCreated_ThresholdBoundary is a synthetic unit test
// proving the 10-day whenCreated threshold logic is correct at its
// boundaries. This detector was flagged "never observed" with no
// plant/revert proof; a fabricated data.Now + fabricated Created timestamps
// is the appropriate way to validate a pure time-threshold check like this
// one - it needs no live lab data.
func TestRecentObjectsCreated_ThresholdBoundary(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		created time.Time
		want    int
	}{
		{"just inside the window (9 days ago) counts", now.AddDate(0, 0, -9), 1},
		{"exactly on the boundary (10 days ago) does not count", now.Add(-10 * 24 * time.Hour), 0},
		{"just outside the window (11 days ago) does not count", now.AddDate(0, 0, -11), 0},
		{"created in the future counts (After(threshold) is true)", now.Add(1 * time.Hour), 1},
		{"zero Created (never collected) does not count", time.Time{}, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Now:   now,
				Users: []types.User{{DN: "CN=u,DC=contoso,DC=com", SAMAccountName: "u", Created: tc.created}},
			}
			findings := NewRecentObjectsDetector().Detect(context.Background(), data)
			if findings[0].Count != tc.want {
				t.Fatalf("Created=%v: expected Count=%d, got %d", tc.created, tc.want, findings[0].Count)
			}
		})
	}
}

// TestRecentObjectsCreated_CountsAcrossAllThreeObjectTypes confirms the
// per-type counters are aggregated into Count and exposed in Details.
func TestRecentObjectsCreated_CountsAcrossAllThreeObjectTypes(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	recent := now.AddDate(0, 0, -1)

	data := &audit.DetectorData{
		Now:       now,
		Users:     []types.User{{DN: "CN=u,DC=contoso,DC=com", SAMAccountName: "u", Created: recent}},
		Computers: []types.Computer{{DN: "CN=c,DC=contoso,DC=com", SAMAccountName: "c$", Created: recent}},
		Groups:    []types.Group{{DN: "CN=g,DC=contoso,DC=com", SAMAccountName: "g", Created: recent}},
	}

	findings := NewRecentObjectsDetector().Detect(context.Background(), data)
	if findings[0].Count != 3 {
		t.Fatalf("expected Count=3 (1 user + 1 computer + 1 group), got %d", findings[0].Count)
	}
	details := findings[0].Details
	if details["newUsers"] != 1 || details["newComputers"] != 1 || details["newGroups"] != 1 {
		t.Fatalf("expected each Details counter to be 1, got %+v", details)
	}
}
