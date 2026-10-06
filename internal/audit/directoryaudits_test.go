package audit

import (
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

func mkAudit(id, cat string, when time.Time) types.DirectoryAudit {
	return types.DirectoryAudit{
		ID:                  id,
		ActivityDateTime:    when,
		ActivityDisplayName: cat + " activity",
		Category:            cat,
	}
}

func TestBuildDirectoryAuditsSummary_NilWhenNoSignal(t *testing.T) {
	if got := BuildDirectoryAuditsSummary(nil, 0, false); got != nil {
		t.Errorf("expected nil for empty events + zero requestedDays, got %+v", got)
	}
}

func TestBuildDirectoryAuditsSummary_EmptyButRequested(t *testing.T) {
	got := BuildDirectoryAuditsSummary(nil, 90, false)
	if got == nil {
		t.Fatal("expected non-nil summary when requestedDays > 0")
	}
	if got.TotalEvents != 0 {
		t.Errorf("TotalEvents = %d, want 0", got.TotalEvents)
	}
	if got.RequestedDays != 90 {
		t.Errorf("RequestedDays = %d, want 90", got.RequestedDays)
	}
	// All 5 categories pre-seeded at 0 so the SaaS analyzer can read keys
	// unconditionally.
	for _, cat := range []string{"RoleManagement", "ConditionalAccess", "ApplicationManagement", "GroupManagement", "UserManagement"} {
		if _, ok := got.ByCategory[cat]; !ok {
			t.Errorf("ByCategory missing key %q", cat)
		}
	}
}

func TestBuildDirectoryAuditsSummary_AggregatesCounts(t *testing.T) {
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	newestExpected := now.Add(-1 * 24 * time.Hour)
	oldestExpected := now.Add(-30 * 24 * time.Hour)
	events := []types.DirectoryAudit{
		mkAudit("a", "RoleManagement", now.Add(-5*24*time.Hour)),
		mkAudit("b", "RoleManagement", now.Add(-3*24*time.Hour)),
		mkAudit("c", "ConditionalAccess", newestExpected),
		mkAudit("d", "ApplicationManagement", oldestExpected),
	}
	got := BuildDirectoryAuditsSummary(events, 90, false)
	if got == nil {
		t.Fatal("nil summary")
	}
	if got.TotalEvents != 4 {
		t.Errorf("TotalEvents = %d, want 4", got.TotalEvents)
	}
	if got.ByCategory["RoleManagement"] != 2 {
		t.Errorf("RoleManagement = %d, want 2", got.ByCategory["RoleManagement"])
	}
	if got.ByCategory["ConditionalAccess"] != 1 {
		t.Errorf("ConditionalAccess = %d, want 1", got.ByCategory["ConditionalAccess"])
	}
	if got.ByCategory["ApplicationManagement"] != 1 {
		t.Errorf("ApplicationManagement = %d, want 1", got.ByCategory["ApplicationManagement"])
	}
	if got.ByCategory["GroupManagement"] != 0 {
		t.Errorf("GroupManagement = %d, want 0 (pre-seeded)", got.ByCategory["GroupManagement"])
	}
	// newest-first sort (events slice is sorted in-place by the helper)
	if got.Events[0].ID != "c" {
		t.Errorf("Events[0].ID = %q, want %q (newest first)", got.Events[0].ID, "c")
	}
	if got.Events[3].ID != "d" {
		t.Errorf("Events[3].ID = %q, want %q (oldest last)", got.Events[3].ID, "d")
	}
	// Bounds (use captured-before-sort references)
	if got.NewestCollected == nil || !got.NewestCollected.Equal(newestExpected) {
		t.Errorf("NewestCollected = %v, want %v", got.NewestCollected, newestExpected)
	}
	if got.OldestCollected == nil || !got.OldestCollected.Equal(oldestExpected) {
		t.Errorf("OldestCollected = %v, want %v", got.OldestCollected, oldestExpected)
	}
	if got.ActualDays != 29 {
		t.Errorf("ActualDays = %d, want 29 (oldest=30d ago, newest=1d ago)", got.ActualDays)
	}
}

func TestBuildDirectoryAuditsSummary_TruncatedFlagPropagated(t *testing.T) {
	now := time.Now().UTC()
	events := []types.DirectoryAudit{mkAudit("a", "RoleManagement", now)}
	got := BuildDirectoryAuditsSummary(events, 90, true)
	if got == nil {
		t.Fatal("nil")
	}
	if !got.Truncated {
		t.Error("Truncated = false, want true")
	}
}
