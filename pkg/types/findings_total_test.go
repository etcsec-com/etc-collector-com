package types

import (
	"encoding/json"
	"strings"
	"testing"
)

// T_036 / B_039 — the repository carried two incompatible "totals" and exported
// only one of them, so no number in the report could be defended:
//
//	engine.go   len(findings)              → finding RECORDS, info included, never exported
//	response.go critical+high+medium+low   → sum of Count, i.e. AFFECTED OBJECTS, info excluded
//
// The retained definition: a finding is one detected defect record, and its
// Count is how many objects that defect affects. Both quantities are published,
// under names that say which is which, and `info` gets its own bucket.

func totalsFixture() *AuditResult {
	return &AuditResult{
		Findings: []Finding{
			{Type: "CRIT_A", Severity: SeverityCritical, Category: "accounts", Count: 3},
			{Type: "HIGH_A", Severity: SeverityHigh, Category: "accounts", Count: 10},
			{Type: "MED_A", Severity: SeverityMedium, Category: "groups", Count: 2},
			{Type: "LOW_A", Severity: SeverityLow, Category: "groups", Count: 1},
			// Informational records: 2 records, 7 affected objects. These are
			// what used to vanish — 364 of them on DC01.
			{Type: "INFO_DOMAIN_OU_INVENTORY", Severity: SeverityInfo, Category: "permissions", Count: 5},
			{Type: "INFO_DOMAIN_GPO_INVENTORY", Severity: SeverityInfo, Category: "permissions", Count: 2},
		},
		Statistics: &AuditStatistics{UsersScanned: 10, UsersEnabled: 10},
	}
}

// TestFindingsSummaryPublishesBothUnits is the acceptance test for Part 3.
func TestFindingsSummaryPublishesBothUnits(t *testing.T) {
	result := totalsFixture()
	resp := ConvertToTSFormat(result, "ad", "ldaps://dc01", "DC=example,DC=com", true)
	f := resp.Audit.Summary.Risk.Findings

	// Unit 1 — affected objects, per severity. Total keeps its historical
	// meaning (info excluded) so existing consumers do not break.
	if f.Critical != 3 || f.High != 10 || f.Medium != 2 || f.Low != 1 {
		t.Errorf("severity buckets = %d/%d/%d/%d, want 3/10/2/1", f.Critical, f.High, f.Medium, f.Low)
	}
	if f.Total != 16 {
		t.Errorf("total = %d, want 16 (3+10+2+1, info excluded)", f.Total)
	}

	// The info findings are counted APART — never silently absent.
	if f.Info != 7 {
		t.Errorf("info = %d, want 7 — informational findings must be visible, not dropped", f.Info)
	}

	// Unit 2 — finding records, info included. This is engine.go's
	// len(findings), exported for the first time.
	if f.Records != 6 {
		t.Errorf("records = %d, want 6 (one per finding record, info included)", f.Records)
	}

	// The two units must not be confusable: on any realistic input they differ,
	// and the report now names both rather than publishing one anonymously.
	if f.Records == f.Total {
		t.Log("note: records == total on this fixture; they are still distinct units")
	}
}

// TestFindingsSummaryIsSelfConsistent — the published numbers must add up, so a
// consultant recounting them lands on the same figures.
func TestFindingsSummaryIsSelfConsistent(t *testing.T) {
	resp := ConvertToTSFormat(totalsFixture(), "ad", "ldaps://dc01", "DC=example,DC=com", true)
	f := resp.Audit.Summary.Risk.Findings

	if got := f.Critical + f.High + f.Medium + f.Low; got != f.Total {
		t.Errorf("critical+high+medium+low = %d but total = %d", got, f.Total)
	}
	if f.Records < 0 || f.Info < 0 {
		t.Errorf("records/info must never be negative: %d/%d", f.Records, f.Info)
	}
}

// TestEngineAndReportAgreeOnRecordCount pins the two former rivals to the same
// value: AuditStatistics.TotalFindings (engine) and findings.records (report)
// are the same quantity, so they can never drift apart again.
func TestEngineAndReportAgreeOnRecordCount(t *testing.T) {
	result := totalsFixture()
	// What engine.calculateStats computes.
	result.Statistics.TotalFindings = len(result.Findings)

	resp := ConvertToTSFormat(result, "ad", "ldaps://dc01", "DC=example,DC=com", true)
	if got := resp.Audit.Summary.Risk.Findings.Records; got != result.Statistics.TotalFindings {
		t.Errorf("report records = %d but engine TotalFindings = %d — the two definitions drifted again",
			got, result.Statistics.TotalFindings)
	}
}

// TestInfoFindingsAreVisibleInTheJSON — the fix is only real if the number
// survives serialisation; `info` had no field at all before.
func TestInfoFindingsAreVisibleInTheJSON(t *testing.T) {
	resp := ConvertToTSFormat(totalsFixture(), "ad", "ldaps://dc01", "DC=example,DC=com", true)
	raw, err := json.Marshal(resp.Audit.Summary.Risk.Findings)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := string(raw)
	for _, key := range []string{`"info":7`, `"records":6`, `"total":16`} {
		if !strings.Contains(out, key) {
			t.Errorf("published summary must contain %s, got %s", key, out)
		}
	}
}
