package controls

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoPlatformFilterDetector checks if any CA policy uses platform-based filtering
type NoPlatformFilterDetector struct {
	audit.BaseDetector
}

// NewNoPlatformFilterDetector creates a new detector
func NewNoPlatformFilterDetector() *NoPlatformFilterDetector {
	return &NoPlatformFilterDetector{
		BaseDetector: audit.NewBaseDetector("CA_NO_PLATFORM_FILTER", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
func (d *NoPlatformFilterDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasPlatformPolicy := false

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State == "enabled" && len(p.IncludePlatforms) > 0 {
			hasPlatformPolicy = true
			break
		}
	}

	count := 0
	if !hasPlatformPolicy {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "No Platform-Based CA Policy",
		Description: "No CA policy filters by device platform. Platform filtering can enforce platform-specific controls.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoPlatformFilterDetector())
}
