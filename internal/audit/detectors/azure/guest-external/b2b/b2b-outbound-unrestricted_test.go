package b2b

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// B2B_OUTBOUND_UNRESTRICTED - RED on current code (count is hardcoded to 1,
// Detect() never reads data), GREEN after wiring it to
// data.AzureCrossTenantAccess.Default.B2BCollaboration.Outbound, already
// collected by engine.go's GetCrossTenantAccessPolicyDefault call.

func detectOutbound(data *audit.DetectorData) types.Finding {
	findings := NewOutboundUnrestrictedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		panic("expected exactly one finding")
	}
	return findings[0]
}

func TestOutboundUnrestricted_NoDataDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{}
	f := detectOutbound(data)
	if f.Count != 0 {
		t.Fatalf("expected count=0 when no cross-tenant policy data was collected, got %d", f.Count)
	}
}

func TestOutboundUnrestricted_RestrictedToGroupDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		AzureCrossTenantAccess: &types.CrossTenantAccessSummary{
			Default: &types.CrossTenantDefaultPolicy{
				B2BCollaboration: types.CrossTenantPolicyChannels{
					Outbound: types.CrossTenantAccessChannel{
						UsersAndGroups: types.CrossTenantAccessTarget{
							AccessType: "allowed",
							Targets:    []string{"11111111-1111-1111-1111-111111111111"},
						},
					},
				},
			},
		},
	}
	f := detectOutbound(data)
	if f.Count != 0 {
		t.Fatalf("expected count=0 when outbound is scoped to a specific group, got %d", f.Count)
	}
}

func TestOutboundUnrestricted_BlockedDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		AzureCrossTenantAccess: &types.CrossTenantAccessSummary{
			Default: &types.CrossTenantDefaultPolicy{
				B2BCollaboration: types.CrossTenantPolicyChannels{
					Outbound: types.CrossTenantAccessChannel{
						UsersAndGroups: types.CrossTenantAccessTarget{
							AccessType: "blocked",
							Targets:    []string{"AllUsers"},
						},
					},
				},
			},
		},
	}
	f := detectOutbound(data)
	if f.Count != 0 {
		t.Fatalf("expected count=0 when outbound is blocked, got %d", f.Count)
	}
}

func TestOutboundUnrestricted_AllUsersAllowedFires(t *testing.T) {
	data := &audit.DetectorData{
		AzureCrossTenantAccess: &types.CrossTenantAccessSummary{
			Default: &types.CrossTenantDefaultPolicy{
				B2BCollaboration: types.CrossTenantPolicyChannels{
					Outbound: types.CrossTenantAccessChannel{
						UsersAndGroups: types.CrossTenantAccessTarget{
							AccessType: "allowed",
							Targets:    []string{"AllUsers"},
						},
					},
				},
			},
		},
	}
	f := detectOutbound(data)
	if f.Count != 1 {
		t.Fatalf("expected count=1 when outbound allows AllUsers, got %d", f.Count)
	}
}
