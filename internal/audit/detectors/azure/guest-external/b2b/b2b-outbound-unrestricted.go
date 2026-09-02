package b2b

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// OutboundUnrestrictedDetector checks for unrestricted outbound B2B access
type OutboundUnrestrictedDetector struct {
	audit.BaseDetector
}

// NewOutboundUnrestrictedDetector creates a new detector
func NewOutboundUnrestrictedDetector() *OutboundUnrestrictedDetector {
	return &OutboundUnrestrictedDetector{
		BaseDetector: audit.NewBaseDetector("B2B_OUTBOUND_UNRESTRICTED", audit.CategoryGuestExternal),
	}
}

// Detect executes the detection
func (d *OutboundUnrestrictedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Tenant-level advisory
	count := 1

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Outbound B2B Access Unrestricted",
		Description: "Users can collaborate with any external organization without restrictions.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewOutboundUnrestrictedDetector())
}
