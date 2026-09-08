package trusts

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestSIDFilteringDisabled_ExternalTrustFlagged is a coverage test, not a
// red/green regression test: no code defect was found in this detector
// (see the Detect doc comment) - the open item was empirical confirmation
// on the lab, which currently carries no trust at all. This pins that an
// external trust without SID filtering is correctly flagged.
func TestSIDFilteringDisabled_ExternalTrustFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TargetDomain: "partner.example", TrustType: "External", SIDFiltering: false},
		},
	}

	findings := NewSIDFilteringDisabledDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
}

// TestSIDFilteringDisabled_ParentChildTrustNotFlagged guards the
// intra-forest skip: SID filtering is not a meaningful boundary between a
// parent and child domain of the same forest.
func TestSIDFilteringDisabled_ParentChildTrustNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TargetDomain: "child.contoso.com", TrustType: "Child", SIDFiltering: false},
		},
	}

	findings := NewSIDFilteringDisabledDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: parent-child trusts are excluded", findings[0].Count)
	}
}
