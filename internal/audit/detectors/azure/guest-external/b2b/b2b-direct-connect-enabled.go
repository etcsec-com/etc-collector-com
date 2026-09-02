package b2b

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DirectConnectEnabledDetector checks if B2B direct connect is enabled
type DirectConnectEnabledDetector struct {
	audit.BaseDetector
}

// NewDirectConnectEnabledDetector creates a new detector
func NewDirectConnectEnabledDetector() *DirectConnectEnabledDetector {
	return &DirectConnectEnabledDetector{
		BaseDetector: audit.NewBaseDetector("B2B_DIRECT_CONNECT_ENABLED", audit.CategoryGuestExternal),
	}
}

// Detect executes the detection
func (d *DirectConnectEnabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Tenant-level advisory
	count := 1

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "B2B Direct Connect Enabled",
		Description: "B2B direct connect allows external users to access resources without being guests.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDirectConnectEnabledDetector())
}
