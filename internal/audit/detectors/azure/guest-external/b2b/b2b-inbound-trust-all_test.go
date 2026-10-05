package b2b

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestInboundTrustAll_NoData_NoFinding(t *testing.T) {
	d := NewInboundTrustAllDetector()
	data := &audit.DetectorData{}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding when no cross-tenant data was collected, got %d", len(findings))
	}
}

func TestInboundTrustAll_RestrictedPolicy_NoFinding(t *testing.T) {
	d := NewInboundTrustAllDetector()
	data := &audit.DetectorData{
		AzureCrossTenantAccess: &types.CrossTenantAccessSummary{
			Default: &types.CrossTenantDefaultPolicy{
				InboundTrust: types.CrossTenantInboundTrust{
					IsMfaAccepted:                       false,
					IsCompliantDeviceAccepted:           false,
					IsHybridAzureADJoinedDeviceAccepted: false,
				},
			},
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding when inbound trust is fully restricted, got %d", len(findings))
	}
}

func TestInboundTrustAll_TrustAcceptedForAll_Fires(t *testing.T) {
	d := NewInboundTrustAllDetector()
	data := &audit.DetectorData{
		AzureCrossTenantAccess: &types.CrossTenantAccessSummary{
			Default: &types.CrossTenantDefaultPolicy{
				InboundTrust: types.CrossTenantInboundTrust{
					IsMfaAccepted: true,
				},
			},
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Fatalf("expected High severity, got %v", findings[0].Severity)
	}
}
