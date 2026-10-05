package hds

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestHDS54LogAccessHealth_NoFabricatedSectionNumber is the red->green test
// for this detector's slice of TestHDSDetectors_NoFabricatedSectionNumbers:
// "HDS 5.4" is not an actual HDS requirement number (Référentiel HDS
// Exigences V1.1.20221027 chapter 5 only runs 5.4-5.10, as generic ISMS
// process clauses - verified against the document's own table of contents).
// Before the fix, the Title/Description asserted "HDS 5.4" as if it were the
// real HDS requirement number for the topic.
func TestHDS54LogAccessHealth_NoFabricatedSectionNumber(t *testing.T) {
	findings := NewHDS54LogAccessHealthDetector().Detect(context.Background(), &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{"{gpo}": {EventAudit: &audit.EventAudit{}}},
	})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	text := findings[0].Title + " " + findings[0].Description
	if strings.Contains(text, "HDS 5.4") {
		t.Errorf("finding still cites the fabricated section number %q as its own requirement: title=%q desc=%q", "HDS 5.4", findings[0].Title, findings[0].Description)
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
