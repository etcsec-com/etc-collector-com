package hds

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestHDSDetectors_NoFabricatedSectionNumbers is the red->green test
// for all five detectors in this file: none of "5.1.4", "5.2", "5.4", "5.8",
// "5.14" is an actual HDS requirement number (Référentiel HDS Exigences
// V1.1.20221027 chapter 5 only runs 5.4-5.10, as generic ISMS process
// clauses - verified against the document's own table of contents). Before
// the fix, every Title/Description below asserted one of these as if it
// were the real HDS requirement number for the topic.
func TestHDSDetectors_NoFabricatedSectionNumbers(t *testing.T) {
	cases := []struct {
		name        string
		detect      func() []types.Finding
		mustNotHave []string
	}{
		{"HDS_5_1_4_STRONG_AUTH", func() []types.Finding {
			return NewHDS514AuthForteDetector().Detect(context.Background(), &audit.DetectorData{Users: []types.User{{SAMAccountName: "u1"}}})
		}, []string{"5.1.4"}},
		{"HDS_5_2_TLS_NOT_ENFORCED", func() []types.Finding {
			return NewHDS52TLSEnforcedDetector().Detect(context.Background(), &audit.DetectorData{})
		}, []string{"HDS 5.2"}},
		{"HDS_5_4_LOG_ACCESS_TO_HEALTH_DATA", func() []types.Finding {
			return NewHDS54LogAccessHealthDetector().Detect(context.Background(), &audit.DetectorData{
				GPOPolicies: map[string]*audit.GPOPolicy{"{gpo}": {EventAudit: &audit.EventAudit{}}},
			})
		}, []string{"HDS 5.4"}},
		{"HDS_5_8_DR_PLAN_MISSING", func() []types.Finding {
			return NewHDS58DRPlanDetector().Detect(context.Background(), &audit.DetectorData{})
		}, []string{"HDS 5.8"}},
		{"HDS_5_14_PENTEST_CADENCE", func() []types.Finding {
			return NewHDS514PentestCadenceDetector().Detect(context.Background(), &audit.DetectorData{})
		}, []string{"HDS 5.14"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := tc.detect()
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d", len(findings))
			}
			text := findings[0].Title + " " + findings[0].Description
			for _, num := range tc.mustNotHave {
				if strings.Contains(text, num) {
					t.Errorf("finding still cites the fabricated section number %q as its own requirement: title=%q desc=%q", num, findings[0].Title, findings[0].Description)
				}
			}
		})
	}
}

// TestHDS54LogAccessHealth_SuccessOnlyStillViolates is the red->green
// test for the threshold bug: before the fix, AuditObjectAccess >= 1 treated
// a Success-only (value 1) or Failure-only (value 2) GPO as compliant, even
// though both the code comment and the finding's own description require
// Success AND Failure (value 3). A Success-only domain must still be
// flagged.
func TestHDS54LogAccessHealth_SuccessOnlyStillViolates(t *testing.T) {
	d := NewHDS54LogAccessHealthDetector()
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{gpo}": {EventAudit: &audit.EventAudit{AuditObjectAccess: 1}}, // Success only
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1 - Success-only auditing does not satisfy a Success+Failure requirement", findings[0].Count)
	}
}

// TestHDS54LogAccessHealth_BothConfigured_NoViolation is the compliant-case
// sanity check paired with the test above.
func TestHDS54LogAccessHealth_BothConfigured_NoViolation(t *testing.T) {
	d := NewHDS54LogAccessHealthDetector()
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{gpo}": {EventAudit: &audit.EventAudit{AuditObjectAccess: 3}}, // Success and Failure
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Errorf("Count = %d, want 0 - Success+Failure auditing is configured", findings[0].Count)
	}
}
