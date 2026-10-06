package hds

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestHDS514AuthForte_NoFabricatedSectionNumber is the red->green test for
// this detector's slice of TestHDSDetectors_NoFabricatedSectionNumbers:
// "5.1.4" is not an actual HDS requirement number (Référentiel HDS Exigences
// V1.1.20221027 chapter 5 only runs 5.4-5.10, as generic ISMS process
// clauses - verified against the document's own table of contents). Before
// the fix, the Title/Description asserted "5.1.4" as if it were the real HDS
// requirement number for the topic.
func TestHDS514AuthForte_NoFabricatedSectionNumber(t *testing.T) {
	findings := NewHDS514AuthForteDetector().Detect(context.Background(), &audit.DetectorData{Users: []types.User{{SAMAccountName: "u1"}}})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	text := findings[0].Title + " " + findings[0].Description
	if strings.Contains(text, "5.1.4") {
		t.Errorf("finding still cites the fabricated section number %q as its own requirement: title=%q desc=%q", "5.1.4", findings[0].Title, findings[0].Description)
	}
}
