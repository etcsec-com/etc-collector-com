package controls

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoTrustedLocationsDetector checks if any trusted locations are configured
type NoTrustedLocationsDetector struct {
	audit.BaseDetector
}

// NewNoTrustedLocationsDetector creates a new detector
func NewNoTrustedLocationsDetector() *NoTrustedLocationsDetector {
	return &NoTrustedLocationsDetector{
		BaseDetector: audit.NewBaseDetector("CA_NO_TRUSTED_LOCATIONS", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
func (d *NoTrustedLocationsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasTrustedLocation := false

	for _, loc := range data.AzureNamedLocations {
		if loc.IsTrusted {
			hasTrustedLocation = true
			break
		}
	}

	count := 0
	if !hasTrustedLocation {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "No Trusted Locations Configured",
		Description: "No named locations are marked as trusted. Trusted locations help reduce MFA friction for known networks.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoTrustedLocationsDetector())
}
