package other

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestDefaultPolicyChanged_RecentChangeFlagged: the
// nominal path hardcoded Count=0 regardless of input (types.GPO had no
// WhenChanged field at all), so this fails until WhenChanged is collected
// and wired through.
func TestDefaultPolicyChanged_RecentChangeFlagged(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	d := NewDefaultPolicyChangedDetector()
	data := &audit.DetectorData{
		Now:            now,
		IncludeDetails: true,
		GPOs: []types.GPO{
			{
				CN:          defaultDomainPolicyGUID,
				GUID:        defaultDomainPolicyGUID,
				DisplayName: "Default Domain Policy",
				WhenChanged: now.AddDate(0, 0, -1), // changed yesterday
			},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 for a default GPO changed within 7 days", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("want 1 affected entity, got %d", len(findings[0].AffectedEntities))
	}
}

// TestDefaultPolicyChanged_OldOrUnknownNotFlagged pins the negative cases:
// a stale change and a missing WhenChanged (zero value, e.g. an older
// collection run) must not produce a false positive.
func TestDefaultPolicyChanged_OldOrUnknownNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	d := NewDefaultPolicyChangedDetector()
	data := &audit.DetectorData{
		Now: now,
		GPOs: []types.GPO{
			{CN: defaultDomainPolicyGUID, GUID: defaultDomainPolicyGUID, WhenChanged: now.AddDate(0, 0, -30)},
			{CN: defaultDCPolicyGUID, GUID: defaultDCPolicyGUID}, // WhenChanged zero: uncollected/unknown
		},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (stale change / unknown WhenChanged must not flag)", findings[0].Count)
	}
}
