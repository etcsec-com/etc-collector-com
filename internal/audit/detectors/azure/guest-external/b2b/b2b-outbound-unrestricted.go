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

// targetIsUnrestricted reports whether a cross-tenant access target scope is
// explicitly "allowed" for the built-in catch-all ("AllUsers"/"AllApplications"),
// i.e. no restriction has been placed on who can go outbound/inbound. Graph's
// default for an unconfigured target is an empty AccessType - absence of
// data must never be read as unrestricted. Shared by every B2B detector in
// this package that reads a CrossTenantAccessTarget.
func targetIsUnrestricted(t types.CrossTenantAccessTarget) bool {
	if t.AccessType != "allowed" {
		return false
	}
	for _, target := range t.Targets {
		if target == "AllUsers" || target == "AllApplications" {
			return true
		}
	}
	return false
}

// Detect executes the detection
func (d *OutboundUnrestrictedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Tenant-level advisory. Outbound restriction status is only measurable
	// when the collector reached /policies/crossTenantAccessPolicy/default
	// (CrossTenantInformation.ReadBasic.All). Without that data we do not
	// guess - no finding is emitted (count stays 0, filtered out upstream).
	count := 0

	if data.AzureCrossTenantAccess != nil && data.AzureCrossTenantAccess.Default != nil {
		out := data.AzureCrossTenantAccess.Default.B2BCollaboration.Outbound
		if targetIsUnrestricted(out.UsersAndGroups) || targetIsUnrestricted(out.Applications) {
			count = 1
		}
	}

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
