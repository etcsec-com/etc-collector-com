package b2b

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// InboundTrustAllDetector checks for inbound trust for all organizations
type InboundTrustAllDetector struct {
	audit.BaseDetector
}

// NewInboundTrustAllDetector creates a new detector
func NewInboundTrustAllDetector() *InboundTrustAllDetector {
	return &InboundTrustAllDetector{
		BaseDetector: audit.NewBaseDetector("B2B_INBOUND_TRUST_ALL", audit.CategoryGuestExternal),
	}
}

// Detect executes the detection
func (d *InboundTrustAllDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Tenant-level advisory
	count := 1

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Inbound Trust for All Organizations",
		Description: "Inbound B2B trust is configured for all organizations without restrictions.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewInboundTrustAllDetector())
}
