package b2b

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// B2B_CROSS_TENANT_OPEN - RED on current code (count is hardcoded to 1,
// Detect() never reads data). Fires only when BOTH inbound and outbound
// B2B collaboration are unrestricted for AllUsers/AllApplications - the
// real "no restrictions at all, any tenant can collaborate" condition.

func TestCrossTenantOpen_NoDataDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{}
	findings := NewCrossTenantOpenDetector().Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding when no cross-tenant data was collected, got %d", len(findings))
	}
}

func TestCrossTenantOpen_OneSideRestrictedDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		AzureCrossTenantAccess: &types.CrossTenantAccessSummary{
			Default: &types.CrossTenantDefaultPolicy{
				B2BCollaboration: types.CrossTenantPolicyChannels{
					Inbound:  types.CrossTenantAccessChannel{UsersAndGroups: types.CrossTenantAccessTarget{AccessType: "allowed", Targets: []string{"AllUsers"}}},
					Outbound: types.CrossTenantAccessChannel{UsersAndGroups: types.CrossTenantAccessTarget{AccessType: "blocked"}},
				},
			},
		},
	}
	findings := NewCrossTenantOpenDetector().Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding when outbound is restricted (only one side open), got %d", len(findings))
	}
}

func TestCrossTenantOpen_BothSidesUnrestrictedFires(t *testing.T) {
	data := &audit.DetectorData{
		AzureCrossTenantAccess: &types.CrossTenantAccessSummary{
			Default: &types.CrossTenantDefaultPolicy{
				B2BCollaboration: types.CrossTenantPolicyChannels{
					Inbound:  types.CrossTenantAccessChannel{UsersAndGroups: types.CrossTenantAccessTarget{AccessType: "allowed", Targets: []string{"AllUsers"}}},
					Outbound: types.CrossTenantAccessChannel{UsersAndGroups: types.CrossTenantAccessTarget{AccessType: "allowed", Targets: []string{"AllUsers"}}},
				},
			},
		},
	}
	findings := NewCrossTenantOpenDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected 1 finding when both inbound and outbound are unrestricted, got %+v", findings)
	}
}
