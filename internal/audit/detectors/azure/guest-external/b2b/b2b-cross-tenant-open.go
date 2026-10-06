package b2b

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CrossTenantOpenDetector checks for open cross-tenant access configuration
type CrossTenantOpenDetector struct {
	audit.BaseDetector
}

// NewCrossTenantOpenDetector creates a new detector
func NewCrossTenantOpenDetector() *CrossTenantOpenDetector {
	return &CrossTenantOpenDetector{
		BaseDetector: audit.NewBaseDetector("B2B_CROSS_TENANT_OPEN", audit.CategoryGuestExternal),
	}
}

// Detect executes the detection
func (d *CrossTenantOpenDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.AzureCrossTenantAccess == nil || data.AzureCrossTenantAccess.Default == nil {
		return nil
	}

	collab := data.AzureCrossTenantAccess.Default.B2BCollaboration
	// "No restrictions configured, any external tenant can collaborate"
	// means BOTH directions are wide open - a restriction on either side
	// alone already limits who can collaborate, so it does not qualify.
	inboundOpen := targetIsUnrestricted(collab.Inbound.UsersAndGroups) || targetIsUnrestricted(collab.Inbound.Applications)
	outboundOpen := targetIsUnrestricted(collab.Outbound.UsersAndGroups) || targetIsUnrestricted(collab.Outbound.Applications)
	if !inboundOpen || !outboundOpen {
		return nil
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Cross-Tenant Access Open",
		Description: "No cross-tenant access restrictions configured. Any external tenant can collaborate.",
		Count:       1,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCrossTenantOpenDetector())
}
