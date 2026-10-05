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
	// AzureAccessReviewsCount/Probed are already collected
	// (GetAccessReviewDefinitionsCount, engine.go) but were never read here.
	// Probed=false means the collection never ran (missing scope, or best-
	// effort call failed) - no verdict, never guess.
	//
	// Scope caveat (source: Microsoft Graph "accessReviewScheduleDefinition
	// resource type", learn.microsoft.com/en-us/graph/api/resources/
	// accessreviewscheduledefinition): a definition's target (guest users vs.
	// any other resource) lives in its `scope`/`instanceEnumerationScope`
	// property, which only supports server-side `$filter` with `contains` -
	// there is no count/filter restricted to guest-scoped reviews without
	// fetching every definition and inspecting its scope individually.
	// GetAccessReviewDefinitionsCount is a tenant-wide $count probe, so
	// AzureAccessReviewsCount==0 proves "no access reviews of any kind exist"
	// (which does imply no guest review exists either), but a tenant whose
	// only configured reviews target non-guest resources would not be caught
	// by this check - see the Description below.
	count := 0
	if data.AzureAccessReviewsProbed && data.AzureAccessReviewsCount == 0 {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "No Guest Access Review Configured",
		Description: "No access review definitions of any kind are configured in this tenant, which means guest access is certainly not being reviewed either. This does not by itself confirm a review scoped to guests exists when the tenant does have access reviews configured - only that zero reviews exist at all.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoAccessReviewDetector())
}
