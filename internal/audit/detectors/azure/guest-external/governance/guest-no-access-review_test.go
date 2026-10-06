package governance

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// GUEST_NO_ACCESS_REVIEW hardcoded count=1 without reading data, even though
// AzureAccessReviewsCount/AzureAccessReviewsProbed are already collected
// (engine.go, GetAccessReviewDefinitionsCount) and unread by any detector.

func TestNoAccessReview_NotProbed_NoVerdict(t *testing.T) {
	d := NewNoAccessReviewDetector()
	data := &audit.DetectorData{AzureAccessReviewsProbed: false}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 when access reviews were never probed, got %d", f.Count)
	}
}

func TestNoAccessReview_ProbedWithReviews_NoFinding(t *testing.T) {
	d := NewNoAccessReviewDetector()
	data := &audit.DetectorData{AzureAccessReviewsProbed: true, AzureAccessReviewsCount: 2}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 when access reviews are configured, got %d", f.Count)
	}
}

func TestNoAccessReview_ProbedZeroReviews_Fires(t *testing.T) {
	d := NewNoAccessReviewDetector()
	data := &audit.DetectorData{AzureAccessReviewsProbed: true, AzureAccessReviewsCount: 0}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 when probed and zero access reviews exist, got %d", f.Count)
	}
}
