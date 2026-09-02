package controls

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoNamedLocationsDetector checks if any named locations are defined
type NoNamedLocationsDetector struct {
	audit.BaseDetector
}

// NewNoNamedLocationsDetector creates a new detector
func NewNoNamedLocationsDetector() *NoNamedLocationsDetector {
	return &NoNamedLocationsDetector{
		BaseDetector: audit.NewBaseDetector("CA_NO_NAMED_LOCATIONS", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
func (d *NoNamedLocationsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := 0
	if len(data.AzureNamedLocations) == 0 {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "No Named Locations Defined",
		Description: "No named locations configured for use in CA policies. Named locations enable location-based access control.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoNamedLocationsDetector())
}
