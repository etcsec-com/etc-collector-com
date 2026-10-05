package hds

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestHDS58DRPlan_NoFabricatedSectionNumber is the red->green test for
// this detector's slice of TestHDSDetectors_NoFabricatedSectionNumbers:
// "HDS 5.8" is not an actual HDS requirement number (Référentiel HDS
// Exigences V1.1.20221027 chapter 5 only runs 5.4-5.10, as generic ISMS
// process clauses - verified against the document's own table of contents).
// Before the fix, the Title/Description asserted "HDS 5.8" as if it were the
// real HDS requirement number for the topic.
func TestHDS58DRPlan_NoFabricatedSectionNumber(t *testing.T) {
	findings := NewHDS58DRPlanDetector().Detect(context.Background(), &audit.DetectorData{})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	text := findings[0].Title + " " + findings[0].Description
	if strings.Contains(text, "HDS 5.8") {
		t.Errorf("finding still cites the fabricated section number %q as its own requirement: title=%q desc=%q", "HDS 5.8", findings[0].Title, findings[0].Description)
	}
}
