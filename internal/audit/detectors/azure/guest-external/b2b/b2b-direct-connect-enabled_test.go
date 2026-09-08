package b2b

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestDirectConnect_NoDataDoesNotGuess(t *testing.T) {
	d := NewDirectConnectEnabledDetector()
	data := &audit.DetectorData{}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 (no data collected, must not guess), got %d", f.Count)
	}
}

func TestDirectConnect_DefaultBlockedNoFinding(t *testing.T) {
	d := NewDirectConnectEnabledDetector()
	data := &audit.DetectorData{
		AzureCrossTenantAccess: &types.CrossTenantAccessSummary{
			Default: &types.CrossTenantDefaultPolicy{
				B2BDirectConnect: types.CrossTenantPolicyChannels{
					Inbound:  types.CrossTenantAccessChannel{UsersAndGroups: types.CrossTenantAccessTarget{AccessType: "blocked"}},
					Outbound: types.CrossTenantAccessChannel{UsersAndGroups: types.CrossTenantAccessTarget{AccessType: "blocked"}},
				},
			},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 (direct connect blocked), got %d", f.Count)
	}
}

func TestDirectConnect_InboundAllowedFires(t *testing.T) {
	d := NewDirectConnectEnabledDetector()
	data := &audit.DetectorData{
		AzureCrossTenantAccess: &types.CrossTenantAccessSummary{
			Default: &types.CrossTenantDefaultPolicy{
				B2BDirectConnect: types.CrossTenantPolicyChannels{
					Inbound: types.CrossTenantAccessChannel{UsersAndGroups: types.CrossTenantAccessTarget{AccessType: "allowed", Targets: []string{"AllUsers"}}},
				},
			},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 (inbound direct connect allowed), got %d", f.Count)
	}
}
