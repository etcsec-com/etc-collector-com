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
	// data.AzureCrossTenantAccess is built in engine.go from
	// GET /policies/crossTenantAccessPolicy/default (Graph). No data
	// collected (nil summary, or default policy absent) => no verdict,
	// per doctrine: never flag without evidence.
	if data.AzureCrossTenantAccess == nil || data.AzureCrossTenantAccess.Default == nil {
		return nil
	}

	trust := data.AzureCrossTenantAccess.Default.InboundTrust
	// The tenant-wide default applies to every external organization that
	// has no per-partner override, so any accepted claim here is a
	// trust-for-all-orgs exposure - an external tenant's MFA/compliant-
	// device/hybrid-join claim is honored without ETC Collector needing
	// to re-verify it.
	if !trust.IsMfaAccepted && !trust.IsCompliantDeviceAccepted && !trust.IsHybridAzureADJoinedDeviceAccepted {
		return nil
	}

	acceptedClaims := make([]string, 0, 3)
	if trust.IsMfaAccepted {
		acceptedClaims = append(acceptedClaims, "isMfaAccepted")
	}
	if trust.IsCompliantDeviceAccepted {
		acceptedClaims = append(acceptedClaims, "isCompliantDeviceAccepted")
	}
	if trust.IsHybridAzureADJoinedDeviceAccepted {
		acceptedClaims = append(acceptedClaims, "isHybridAzureADJoinedDeviceAccepted")
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Inbound Trust for All Organizations",
		Description: "The tenant-wide default cross-tenant access policy accepts external-tenant MFA/device claims for all organizations without a per-partner restriction.",
		Count:       1,
		Details: map[string]interface{}{
			"acceptedClaims": acceptedClaims,
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewInboundTrustAllDetector())
}
