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

// B_075/T_069 — "neither signal could be probed" must be visible in the
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

// Documents a known, deliberately unresolved edge case: when ONE signal is
// probed (PIM, shows adoption) and the OTHER is not (access reviews), the
// detector still returns silence rather than an Info finding — it only
// distinguishes "totally blind" (neither signal available) from "at least
// one real verdict". A report reader cannot tell "both checked, compliant"
// from "one checked, one unknown" from this output alone. Flagged in the
// T_069 delivery as a follow-up rather than solved here — pinned by this
// test so a future fix changes it on purpose, not by accident.
func TestP2NotFullyUtilized_PartialProbe_KnownLimitation(t *testing.T) {
	d := NewP2NotFullyUtilizedDetector()
	data := &audit.DetectorData{
		AzureLicenseTier:    "p2",
		AzurePIMAssignments: &types.PIMAssignmentsSummary{Eligible: types.PIMEligibleSummary{Total: 3}},
		// AzureAccessReviewsProbed left false — only PIM could be probed this run.
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("current (imperfect) behavior: silent when the available signal shows adoption, got %+v", findings)
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
