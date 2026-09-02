// Package audit — directory audits aggregation (v3.1.36).
//
// Pure post-collection aggregator. Takes the raw events returned by
// providers/azure.GetDirectoryAudits and produces the
// types.DirectoryAuditsSummary that lands at audit.directoryAudits in the
// final payload.
//
// No I/O — deterministic for a given (events, requestedDays, truncated)
// triple. The collector layer (engine.collectAzureData) owns the Graph
// roundtrip and the sub-context budget; this file only shapes the result.

package audit

import (
	"sort"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// BuildDirectoryAuditsSummary aggregates raw events into the SaaS-facing
// summary. Returns nil when there's nothing to expose (empty events AND
// requestedDays == 0) so audit.directoryAudits is omitted from the payload
// — clean signal that the feature wasn't requested or the call failed.
//
// When events is empty but requestedDays > 0, returns an empty summary
// with totalEvents=0 / events=[]. That tells the SaaS "we asked, the tenant
// is just quiet" — a different signal from "we didn't ask".
func BuildDirectoryAuditsSummary(events []types.DirectoryAudit, requestedDays int, truncated bool) *types.DirectoryAuditsSummary {
	if len(events) == 0 && requestedDays == 0 {
		return nil
	}

	summary := &types.DirectoryAuditsSummary{
		TotalEvents:   len(events),
		ByCategory:    make(map[string]int, 5),
		Truncated:     truncated,
		RequestedDays: requestedDays,
		Events:        events,
	}

	// Pre-seed the 5 known categories at 0 so the SaaS analyzer can rely on
	// the keys always being present (avoids `category in keys ? counts[c] : 0`
	// guards on every UI tile).
	for _, cat := range []string{
		"RoleManagement",
		"ConditionalAccess",
		"ApplicationManagement",
		"GroupManagement",
		"UserManagement",
	} {
		summary.ByCategory[cat] = 0
	}

	var newest, oldest *types.DirectoryAudit
	for i := range events {
		ev := &events[i]
		summary.ByCategory[ev.Category]++
		if newest == nil || ev.ActivityDateTime.After(newest.ActivityDateTime) {
			newest = ev
		}
		if oldest == nil || ev.ActivityDateTime.Before(oldest.ActivityDateTime) {
			oldest = ev
		}
	}
	if newest != nil {
		t := newest.ActivityDateTime
		summary.NewestCollected = &t
	}
	if oldest != nil {
		t := oldest.ActivityDateTime
		summary.OldestCollected = &t
	}

	// ActualDays — the real lookback window covered by events[]. When
	// truncated the budget cap may have stopped pagination before the
	// 90-day floor was reached, so the SaaS dashboard uses ActualDays
	// (not RequestedDays) when labelling the timeline span.
	if newest != nil && oldest != nil {
		span := newest.ActivityDateTime.Sub(oldest.ActivityDateTime)
		days := int(span.Hours() / 24)
		if days < 0 {
			days = 0
		}
		summary.ActualDays = days
	}

	// Sort events newest-first — matches the Graph $orderby=activityDateTime
	// desc the goroutines requested, and the SaaS Identity Drift Timeline
	// renders top-down chronologically.
	sort.SliceStable(summary.Events, func(i, j int) bool {
		return summary.Events[i].ActivityDateTime.After(summary.Events[j].ActivityDateTime)
	})

	return summary
}
