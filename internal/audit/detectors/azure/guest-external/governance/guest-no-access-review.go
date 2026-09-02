package governance

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoAccessReviewDetector checks for missing guest access review configuration
type NoAccessReviewDetector struct {
	audit.BaseDetector
}

// NewNoAccessReviewDetector creates a new detector
func NewNoAccessReviewDetector() *NoAccessReviewDetector {
	return &NoAccessReviewDetector{
		BaseDetector: audit.NewBaseDetector("GUEST_NO_ACCESS_REVIEW", audit.CategoryGuestExternal),
	}
}

// Detect executes the detection
func (d *NoAccessReviewDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Tenant-level advisory
	count := 1

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "No Guest Access Review Configured",
		Description: "No automated access reviews for guest users. Regular reviews prevent stale external access.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoAccessReviewDetector())
}
