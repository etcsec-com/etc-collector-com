package licensing

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestP2NotFullyUtilized_SilentWithoutP2(t *testing.T) {
	d := NewP2NotFullyUtilizedDetector()
	data := &audit.DetectorData{AzureLicenseTier: "p1"}

	if findings := d.Detect(context.Background(), data); len(findings) != 0 {
		t.Fatalf("expected no finding without P2, got %+v", findings)
	}
}

func TestP2NotFullyUtilized_SilentWhenFeaturesUsed(t *testing.T) {
	d := NewP2NotFullyUtilizedDetector()
	data := &audit.DetectorData{
		AzureLicenseTier:         "p2",
		AzurePIMAssignments:      &types.PIMAssignmentsSummary{Eligible: types.PIMEligibleSummary{Total: 3}},
		AzureAccessReviewsProbed: true,
		AzureAccessReviewsCount:  2,
	}

	if findings := d.Detect(context.Background(), data); len(findings) != 0 {
		t.Fatalf("expected no finding when PIM and access reviews are both used, got %+v", findings)
	}
}

// "neither signal could be probed" must be visible in the
// report, distinct from both a real finding and real silence: an
// Info-severity finding, not nil.
func TestP2NotFullyUtilized_InfoFindingWhenNotProbed(t *testing.T) {
	d := NewP2NotFullyUtilizedDetector()
	data := &audit.DetectorData{AzureLicenseTier: "p2"} // AzurePIMAssignments nil, AccessReviewsProbed false

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (visible ignorance) when neither signal could be probed, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityInfo {
		t.Fatalf("expected Info severity when unprobed, got %s", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Title, "not determinable") {
		t.Fatalf("title must say the check wasn't determinable, got %q", findings[0].Title)
	}
}

// Fixes an edge case previously flagged and deliberately left unresolved
// (pinned by the test this replaces): when ONE signal is probed
// (PIM, shows adoption) and the OTHER is not (access reviews), the detector
// used to return silence - indistinguishable from "both checked, compliant".
// It must now surface an Info finding instead: a real tenant hit exactly
// this (P2 active, PIM eligible.Total=2, access-reviews probe failed for
// missing permission) and got silently treated as "fully utilized".
func TestP2NotFullyUtilized_PartialProbe_NowSurfacesInfoFinding(t *testing.T) {
	d := NewP2NotFullyUtilizedDetector()
	data := &audit.DetectorData{
		AzureLicenseTier:    "p2",
		AzurePIMAssignments: &types.PIMAssignmentsSummary{Eligible: types.PIMEligibleSummary{Total: 2}},
		// AzureAccessReviewsProbed left false - only PIM could be probed this run.
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (visible partial ignorance), got %+v", findings)
	}
	if findings[0].Severity != types.SeverityInfo {
		t.Fatalf("expected Info severity for a partially-probed result, got %s", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Title, "partially determinable") {
		t.Fatalf("title must say the check was only partially determinable, got %q", findings[0].Title)
	}
	if !strings.Contains(findings[0].Description, "access reviews") {
		t.Fatalf("description must name the unprobed signal, got %q", findings[0].Description)
	}
}

// Same partial-probe shape, but this time it's access reviews that was
// probed (and empty) while PIM was never probed - the Medium-severity real
// finding (reasons non-empty) must still win over the Info framing.
func TestP2NotFullyUtilized_PartialProbe_RealGapStillWins(t *testing.T) {
	d := NewP2NotFullyUtilizedDetector()
	data := &audit.DetectorData{
		AzureLicenseTier:         "p2",
		AzureAccessReviewsProbed: true,
		AzureAccessReviewsCount:  0,
		// AzurePIMAssignments left nil - PIM could not be probed this run.
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %+v", findings)
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Fatalf("a confirmed unused access-reviews signal must still produce a Medium finding, got %s", findings[0].Severity)
	}
}

func TestP2NotFullyUtilized_FiresOnUnusedPIM(t *testing.T) {
	d := NewP2NotFullyUtilizedDetector()
	data := &audit.DetectorData{
		AzureLicenseTier:         "p2",
		AzurePIMAssignments:      &types.PIMAssignmentsSummary{Eligible: types.PIMEligibleSummary{Total: 0}},
		AzureAccessReviewsProbed: true,
		AzureAccessReviewsCount:  2,
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when PIM has zero eligible assignments, got %d", len(findings))
	}
}

func TestP2NotFullyUtilized_FiresOnUnusedAccessReviews(t *testing.T) {
	d := NewP2NotFullyUtilizedDetector()
	data := &audit.DetectorData{
		AzureLicenseTier:         "p2",
		AzurePIMAssignments:      &types.PIMAssignmentsSummary{Eligible: types.PIMEligibleSummary{Total: 3}},
		AzureAccessReviewsProbed: true,
		AzureAccessReviewsCount:  0,
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when access reviews are probed and empty, got %d", len(findings))
	}
}
