package anssi

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R42 previously had no test file of its own (its cases lived in
// phase_b_test.go, built on the removed types.Trust.PasswordLastSet field).

var r42TestNow = time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)

func r42DaysAgo(n int) time.Time { return r42TestNow.AddDate(0, 0, -n) }

func detect(t *testing.T, data *audit.DetectorData) *types.Finding {
	t.Helper()
	findings := NewR42TrustPasswordOldDetector().Detect(context.Background(), data)
	if len(findings) == 0 {
		return nil
	}
	if len(findings) > 1 {
		t.Fatalf("expected at most 1 finding, got %d", len(findings))
	}
	return &findings[0]
}

func TestR42_OutgoingMetadata_60Days_Triggers(t *testing.T) {
	data := &audit.DetectorData{
		Now:            r42TestNow,
		IncludeDetails: true,
		Trusts: []types.Trust{{
			TargetDomain:           "out.example.com",
			TrustDirection:         "Outbound",
			OutgoingPasswordDate:   r42DaysAgo(60),
			OutgoingPasswordSource: "replmetadata",
		}},
	}
	f := detect(t, data)
	if f == nil || f.Count != 1 || f.Severity != types.SeverityMedium {
		t.Fatalf("expected Count 1 Medium, got %+v", f)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].Name != "out.example.com" {
		t.Fatalf("AffectedEntities = %+v, want exactly [out.example.com]", f.AffectedEntities)
	}
	if f.Reproducibility == nil || f.Reproducibility.LDAPFilter == "" {
		t.Fatalf("R42 must emit reproducibility.ldapFilter when triggered, got %+v", f.Reproducibility)
	}
	for _, a := range f.Reproducibility.LDAPAttrs {
		if a == "pwdLastSet" {
			t.Fatalf("reproducibility must not ask for pwdLastSet on the trustedDomain object, got attrs %v", f.Reproducibility.LDAPAttrs)
		}
	}
	details, ok := f.Details["trusts"].([]map[string]interface{})
	if !ok || len(details) != 1 {
		t.Fatalf("Details[\"trusts\"] = %#v, want exactly 1 entry", f.Details["trusts"])
	}
	if details[0]["source"] != "replmetadata" || details[0]["direction"] != "outgoing" {
		t.Fatalf("detail = %+v, want source=replmetadata direction=outgoing", details[0])
	}
}

// TestR42_Boundary59NoFinding_60Triggers fixes the exact `>=` boundary at
// the Medium threshold.
func TestR42_Boundary59NoFinding_60Triggers(t *testing.T) {
	base := func(age int) *audit.DetectorData {
		return &audit.DetectorData{
			Now: r42TestNow,
			Trusts: []types.Trust{{
				TargetDomain: "boundary.example.com", TrustDirection: "Outbound",
				OutgoingPasswordDate: r42DaysAgo(age), OutgoingPasswordSource: "replmetadata",
			}},
		}
	}
	if f := detect(t, base(59)); f != nil {
		t.Fatalf("59 days should not trigger, got %+v", f)
	}
	if f := detect(t, base(60)); f == nil || f.Severity != types.SeverityMedium {
		t.Fatalf("60 days should trigger Medium, got %+v", f)
	}
}

// TestR42_Boundary89Medium_90High fixes the exact `>=` boundary at the High
// threshold - 89 days stays Medium, 90 escalates.
func TestR42_Boundary89Medium_90High(t *testing.T) {
	base := func(age int) *audit.DetectorData {
		return &audit.DetectorData{
			Now: r42TestNow,
			Trusts: []types.Trust{{
				TargetDomain: "boundary.example.com", TrustDirection: "Outbound",
				OutgoingPasswordDate: r42DaysAgo(age), OutgoingPasswordSource: "replmetadata",
			}},
		}
	}
	if f := detect(t, base(89)); f == nil || f.Severity != types.SeverityMedium {
		t.Fatalf("89 days should be Medium, got %+v", f)
	}
	if f := detect(t, base(90)); f == nil || f.Severity != types.SeverityHigh {
		t.Fatalf("90 days should be High, got %+v", f)
	}
}

func TestR42_IncomingTrustAccountOnly_Triggers(t *testing.T) {
	data := &audit.DetectorData{
		Now:            r42TestNow,
		IncludeDetails: true,
		Trusts: []types.Trust{{
			TargetDomain:           "in.example.com",
			TrustDirection:         "Inbound",
			IncomingPasswordDate:   r42DaysAgo(70),
			IncomingPasswordSource: "trust_account",
		}},
	}
	f := detect(t, data)
	if f == nil || f.Count != 1 || f.Severity != types.SeverityMedium {
		t.Fatalf("expected Count 1 Medium, got %+v", f)
	}
	details := f.Details["trusts"].([]map[string]interface{})
	if details[0]["source"] != "trust_account" || details[0]["direction"] != "incoming" {
		t.Fatalf("detail = %+v, want source=trust_account direction=incoming", details[0])
	}
}

func TestR42_BidirectionalOneStaleOneFresh_TriggersOnStaleDirectionOnly(t *testing.T) {
	data := &audit.DetectorData{
		Now:            r42TestNow,
		IncludeDetails: true,
		Trusts: []types.Trust{{
			TargetDomain:           "half.example.com",
			TrustDirection:         "Bidirectional",
			OutgoingPasswordDate:   r42DaysAgo(100),
			OutgoingPasswordSource: "replmetadata",
			IncomingPasswordDate:   r42DaysAgo(5),
			IncomingPasswordSource: "replmetadata",
		}},
	}
	f := detect(t, data)
	if f == nil || f.Count != 1 || f.Severity != types.SeverityHigh {
		t.Fatalf("expected Count 1 High (outgoing at 100 days), got %+v", f)
	}
	details := f.Details["trusts"].([]map[string]interface{})
	if len(details) != 1 || details[0]["direction"] != "outgoing" {
		t.Fatalf("details = %+v, want exactly the outgoing direction (incoming is fresh)", details)
	}
}

// TestR42_NoExactDate_WhenChangedBoundOld_Triggers exercises the
// whenChanged-as-bound fallback when neither replmetadata nor the trust
// account produced an exact reading.
func TestR42_NoExactDate_WhenChangedBoundOld_Triggers(t *testing.T) {
	data := &audit.DetectorData{
		Now:            r42TestNow,
		IncludeDetails: true,
		Trusts: []types.Trust{{
			TargetDomain: "bound-only.example.com", TrustDirection: "Outbound",
			WhenChanged: r42DaysAgo(95),
		}},
	}
	f := detect(t, data)
	if f == nil || f.Severity != types.SeverityHigh {
		t.Fatalf("expected High via whenChanged bound at 95 days, got %+v", f)
	}
	details := f.Details["trusts"].([]map[string]interface{})
	if details[0]["source"] != "whenChanged bound" {
		t.Fatalf("detail source = %v, want \"whenChanged bound\"", details[0]["source"])
	}
}

// TestR42_NoExactDate_WhenChangedBoundRecent_NoFinding: the bound alone is
// too young to prove staleness - the detector must not fire (never a claim
// of "recent", just insufficient evidence to flag).
func TestR42_NoExactDate_WhenChangedBoundRecent_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		Now: r42TestNow,
		Trusts: []types.Trust{{
			TargetDomain: "bound-fresh.example.com", TrustDirection: "Outbound",
			WhenChanged: r42DaysAgo(10),
		}},
	}
	if f := detect(t, data); f != nil {
		t.Fatalf("expected no finding (bound too young), got %+v", f)
	}
}

// TestR42_NoDataAtAll_Silence: no exact reading, no whenChanged - the
// detector must stay silent rather than guess.
func TestR42_NoDataAtAll_Silence(t *testing.T) {
	data := &audit.DetectorData{
		Now: r42TestNow,
		Trusts: []types.Trust{{TargetDomain: "no-data.example.com", TrustDirection: "Outbound"}},
	}
	if f := detect(t, data); f != nil {
		t.Fatalf("expected no finding (no date at all), got %+v", f)
	}
}

// TestR42_MetadataOldButWhenChangedRecent_StillTriggers is a lab-measured
// trap: whenChanged can be NEWER than the real secret write (a TDO's
// msDS-TrustForestTrustInfo rewrite moved whenChanged several minutes past
// trustAuthOutgoing/Incoming on a live lab domain). The exact reading must
// win even though the bound alone would look fresh. Verified by mutation
// (in trustDirectionAge, checking whenChanged before exactSource) during
// development: this test alone caught it, going red before the fix was
// reverted.
func TestR42_MetadataOldButWhenChangedRecent_StillTriggers(t *testing.T) {
	data := &audit.DetectorData{
		Now: r42TestNow,
		Trusts: []types.Trust{{
			TargetDomain:           "stale-but-touched.example.com",
			TrustDirection:         "Outbound",
			OutgoingPasswordDate:   r42DaysAgo(100),
			OutgoingPasswordSource: "replmetadata",
			WhenChanged:            r42DaysAgo(5),
		}},
	}
	f := detect(t, data)
	if f == nil || f.Severity != types.SeverityHigh {
		t.Fatalf("expected High (exact metadata age must win over a recent whenChanged), got %+v", f)
	}
}

// TestR42_MIT_Excluded: no automatic rotation exists for a MIT realm to
// escape - R42's premise does not apply. Verified by mutation (removing
// the MIT skip in Detect) during development: this test alone caught it,
// going red before the fix was reverted.
func TestR42_MIT_Excluded(t *testing.T) {
	data := &audit.DetectorData{
		Now: r42TestNow,
		Trusts: []types.Trust{{
			TargetDomain:           "realm.example.com",
			TrustDirection:         "Bidirectional",
			TrustProtocolType:      "MIT",
			OutgoingPasswordDate:   r42DaysAgo(400),
			OutgoingPasswordSource: "replmetadata",
			IncomingPasswordDate:   r42DaysAgo(400),
			IncomingPasswordSource: "replmetadata",
		}},
	}
	if f := detect(t, data); f != nil {
		t.Fatalf("expected no finding (MIT excluded), got %+v", f)
	}
}

// TestR42_DisabledDirection_NoFinding: trustDirection 0 leaves
// TrustDirection empty - no direction is evaluated.
func TestR42_DisabledDirection_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		Now: r42TestNow,
		Trusts: []types.Trust{
			{TargetDomain: "disabled.example.com", TrustDirection: "", WhenChanged: r42DaysAgo(400)},
		},
	}
	if f := detect(t, data); f != nil {
		t.Fatalf("expected no finding (disabled trust, no direction to evaluate), got %+v", f)
	}
}

// TestR42_Boundary90CriticalThreshold pins the exact High threshold: a
// threshold shifted by a single day must be visible at 90 days exactly.
// Verified by mutation (changing trustPasswordCriticalDays from 90 to 91)
// during development: this test (with TestR42_Boundary89Medium_90High)
// caught it, going red before the fix was reverted.
func TestR42_Boundary90CriticalThreshold(t *testing.T) {
	data := &audit.DetectorData{
		Now: r42TestNow,
		Trusts: []types.Trust{{
			TargetDomain: "ninety.example.com", TrustDirection: "Outbound",
			OutgoingPasswordDate: r42DaysAgo(90), OutgoingPasswordSource: "replmetadata",
		}},
	}
	f := detect(t, data)
	if f == nil || f.Severity != types.SeverityHigh {
		t.Fatalf("90 days must be High, got %+v", f)
	}
}

// TestR42_BidirectionalFreshOutgoingStaleIncoming_MediumOneDetail (T-MV4) is
// the mirror of TestR42_BidirectionalOneStaleOneFresh_TriggersOnStaleDirectionOnly:
// outgoing fresh (J-5), incoming stale (J-70, Medium range) - the finding
// must fire Medium with exactly one detail, direction incoming. Before this
// test, no case in this file exercised "incoming alone is the stale
// direction" - every case here either had outgoing alone stale, or an
// incoming-only trust.
// Verified by mutation (passing OutgoingPasswordDate/Source instead of
// IncomingPasswordDate/Source to the "incoming" checkDirection call) during
// development: this test alone caught it, going red before the fix was
// reverted.
func TestR42_BidirectionalFreshOutgoingStaleIncoming_MediumOneDetail(t *testing.T) {
	data := &audit.DetectorData{
		Now:            r42TestNow,
		IncludeDetails: true,
		Trusts: []types.Trust{{
			TargetDomain:           "incoming-stale.example.com",
			TrustDirection:         "Bidirectional",
			OutgoingPasswordDate:   r42DaysAgo(5),
			OutgoingPasswordSource: "replmetadata",
			IncomingPasswordDate:   r42DaysAgo(70),
			IncomingPasswordSource: "replmetadata",
		}},
	}
	f := detect(t, data)
	if f == nil || f.Count != 1 || f.Severity != types.SeverityMedium {
		t.Fatalf("expected Count 1 Medium (incoming at 70 days), got %+v", f)
	}
	details := f.Details["trusts"].([]map[string]interface{})
	if len(details) != 1 || details[0]["direction"] != "incoming" {
		t.Fatalf("details = %+v, want exactly the incoming direction (outgoing is fresh)", details)
	}
}

// TestR42_BidirectionalBothStale_DedupedCountTwoDetails (T-MV5): both
// directions of the SAME trust are stale (J-70 each, Medium range) - the
// trust must be counted ONCE in Count (staleTrustDomains dedup), but carry
// TWO entries in Details["trusts"], one per direction.
// Verified by mutation (removing the `if !staleTrustDomains[...]` dedup
// guard, always appending to staleOrder) during development: this test alone
// caught it, going red before the fix was reverted.
func TestR42_BidirectionalBothStale_DedupedCountTwoDetails(t *testing.T) {
	data := &audit.DetectorData{
		Now:            r42TestNow,
		IncludeDetails: true,
		Trusts: []types.Trust{{
			TargetDomain:           "both-stale.example.com",
			TrustDirection:         "Bidirectional",
			OutgoingPasswordDate:   r42DaysAgo(70),
			OutgoingPasswordSource: "replmetadata",
			IncomingPasswordDate:   r42DaysAgo(70),
			IncomingPasswordSource: "replmetadata",
		}},
	}
	f := detect(t, data)
	if f == nil || f.Count != 1 {
		t.Fatalf("expected Count 1 (one trust, deduped across its two stale directions), got %+v", f)
	}
	if len(f.AffectedEntities) != 1 {
		t.Fatalf("expected exactly 1 affected entity, got %+v", f.AffectedEntities)
	}
	details := f.Details["trusts"].([]map[string]interface{})
	if len(details) != 2 {
		t.Fatalf("expected 2 details (one per stale direction), got %+v", details)
	}
}

// TestR42_TwoOutgoingTrusts_WorstSeverityWins (T-MV6): two SEPARATE trusts,
// both Outbound-only - the first at J-100 (High range), the second at J-70
// (Medium range). severity is a single variable shared across the whole
// Detect() loop; it must reflect the WORST case across every trust
// evaluated, not whichever trust happened to be processed last.
// Verified by mutation (adding an `else { severity = types.SeverityMedium }`
// branch to the age>=critical check, so a later Medium-range trust downgrades
// an earlier High back to Medium) during development: this test alone caught
// it, going red before the fix was reverted.
func TestR42_TwoOutgoingTrusts_WorstSeverityWins(t *testing.T) {
	data := &audit.DetectorData{
		Now:            r42TestNow,
		IncludeDetails: true,
		Trusts: []types.Trust{
			{
				TargetDomain:           "first-critical.example.com",
				TrustDirection:         "Outbound",
				OutgoingPasswordDate:   r42DaysAgo(100),
				OutgoingPasswordSource: "replmetadata",
			},
			{
				TargetDomain:           "second-medium.example.com",
				TrustDirection:         "Outbound",
				OutgoingPasswordDate:   r42DaysAgo(70),
				OutgoingPasswordSource: "replmetadata",
			},
		},
	}
	f := detect(t, data)
	if f == nil || f.Count != 2 || f.Severity != types.SeverityHigh {
		t.Fatalf("expected Count 2 High (worst case across both trusts must win, even processed second), got %+v", f)
	}
}

func TestR42_NoTrusts_NoFinding(t *testing.T) {
	data := &audit.DetectorData{Now: r42TestNow}
	if f := detect(t, data); f != nil {
		t.Fatalf("expected nil for zero trusts, got %+v", f)
	}
}

// TestR42_DescriptionMatchesDoc pins runtime Description text against the
// generated Doc() - the two must never drift (cataloggen regenerates Doc()
// from this exact string).
func TestR42_DescriptionMatchesDoc(t *testing.T) {
	d := NewR42TrustPasswordOldDetector()
	data := &audit.DetectorData{
		Now: r42TestNow,
		Trusts: []types.Trust{{
			TargetDomain: "desc.example.com", TrustDirection: "Outbound",
			OutgoingPasswordDate: r42DaysAgo(60), OutgoingPasswordSource: "replmetadata",
		}},
	}
	f := detect(t, data)
	if f == nil {
		t.Fatal("expected a finding to compare Description against Doc()")
	}
	doc := d.Doc()
	// Doc() keeps the raw fmt template (%d placeholders); the runtime
	// Description is the same template with count/days substituted in - so
	// the equality check substitutes the same values back in rather than
	// comparing the two literally, which would never match a Sprintf-based
	// detector.
	wantDescription := fmt.Sprintf(doc.Description, 1, trustPasswordWarnDays)
	if f.Description != wantDescription {
		t.Fatalf("runtime Description and Doc() template have drifted:\nruntime: %s\ndoc:     %s", f.Description, doc.Description)
	}
	if strings.Contains(doc.Description, "quarterly review cycle has gone by") {
		t.Fatal("Doc() still carries the old wording that attributes a fixed cycle length to ANSSI")
	}
}
