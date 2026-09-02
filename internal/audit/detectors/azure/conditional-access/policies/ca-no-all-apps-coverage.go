package policies

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoAllAppsCoverageDetector checks if any CA policy covers all cloud apps
type NoAllAppsCoverageDetector struct {
	audit.BaseDetector
}

// NewNoAllAppsCoverageDetector creates a new detector
func NewNoAllAppsCoverageDetector() *NoAllAppsCoverageDetector {
	return &NoAllAppsCoverageDetector{
		BaseDetector: audit.NewBaseDetector("CA_NO_ALL_APPS_COVERAGE", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
func (d *NoAllAppsCoverageDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasAllAppsPolicy := false

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State == "enabled" && containsStr(p.IncludeApps, "All") {
			hasAllAppsPolicy = true
			break
		}
	}

	count := 0
	if !hasAllAppsPolicy {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "No CA Policy Covers All Cloud Apps",
		Description: "No CA policy targets all cloud applications. Individual app targeting may leave gaps.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoAllAppsCoverageDetector())
}
