package controls

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoLocationBlockDetector checks if any CA policy uses location-based blocking
type NoLocationBlockDetector struct {
	audit.BaseDetector
}

// NewNoLocationBlockDetector creates a new detector
func NewNoLocationBlockDetector() *NoLocationBlockDetector {
	return &NoLocationBlockDetector{
		BaseDetector: audit.NewBaseDetector("CA_NO_LOCATION_BLOCK", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
func (d *NoLocationBlockDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasLocationPolicy := false

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State == "enabled" && len(p.IncludeLocations) > 0 {
			hasLocationPolicy = true
			break
		}
	}

	count := 0
	if !hasLocationPolicy {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "No Location-Based Access Blocking",
		Description: "No CA policy uses location conditions to block access from untrusted locations.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoLocationBlockDetector())
}
