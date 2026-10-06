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

// channelAllowsDirectConnect reports whether either scope (users/groups or
// applications) of one inbound/outbound channel is explicitly "allowed".
// Graph's default for an unconfigured channel is "blocked" - absence of
// data (empty AccessType) must never be read as enabled.
func channelAllowsDirectConnect(ch types.CrossTenantAccessChannel) bool {
	return ch.UsersAndGroups.AccessType == "allowed" || ch.Applications.AccessType == "allowed"
}

// Detect executes the detection
func (d *DirectConnectEnabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Tenant-level advisory. Direct Connect status is only measurable when
	// the collector reached /policies/crossTenantAccessPolicy/default
	// (CrossTenantInformation.ReadBasic.All). Without that data we do not
	// guess - no finding is emitted (count stays 0, filtered out upstream).
	count := 0

	if data.AzureCrossTenantAccess != nil && data.AzureCrossTenantAccess.Default != nil {
		dc := data.AzureCrossTenantAccess.Default.B2BDirectConnect
		if channelAllowsDirectConnect(dc.Inbound) || channelAllowsDirectConnect(dc.Outbound) {
			count = 1
		}
	}

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
