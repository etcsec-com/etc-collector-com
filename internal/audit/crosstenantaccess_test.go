package audit

import (
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestBuildCrossTenantAccessSummary_AllNilReturnsNil(t *testing.T) {
	if got := BuildCrossTenantAccessSummary(nil, nil, nil); got != nil {
		t.Errorf("all-nil input must return nil to keep the JSON output clean, got %#v", got)
	}
}

func TestBuildCrossTenantAccessSummary_DefaultOnly(t *testing.T) {
	def := &types.CrossTenantDefaultPolicy{
		InboundTrust: types.CrossTenantInboundTrust{
			IsMfaAccepted: true,
		},
	}
	got := BuildCrossTenantAccessSummary(def, nil, nil)
	if got == nil || got.Default == nil || !got.Default.InboundTrust.IsMfaAccepted {
		t.Fatalf("default-only summary mismatch: %#v", got)
	}
	if len(got.Partners) != 0 || got.MultiTenantOrganization != nil {
		t.Errorf("partners and MTO must remain empty/nil, got partners=%d mto=%v", len(got.Partners), got.MultiTenantOrganization)
	}
}

func TestBuildCrossTenantAccessSummary_DefaultPlusPartners(t *testing.T) {
	def := &types.CrossTenantDefaultPolicy{}
	partners := []types.CrossTenantPartnerPolicy{
		{TenantID: "t-1", DisplayName: "Acme"},
		{TenantID: "t-2", IsServiceProvider: true},
	}
	got := BuildCrossTenantAccessSummary(def, partners, nil)
	if got == nil || len(got.Partners) != 2 {
		t.Fatalf("partners must pass through, got %#v", got)
	}
	if got.Partners[1].IsServiceProvider != true {
		t.Errorf("isServiceProvider drop")
	}
}

func TestBuildCrossTenantAccessSummary_FullPayload(t *testing.T) {
	got := BuildCrossTenantAccessSummary(
		&types.CrossTenantDefaultPolicy{},
		[]types.CrossTenantPartnerPolicy{{TenantID: "t-1"}},
		&types.CrossTenantMultiTenantOrg{IsEnabled: true, TenantsCount: 3},
	)
	if got == nil || got.Default == nil || len(got.Partners) != 1 || got.MultiTenantOrganization == nil {
		t.Fatalf("full payload mismatch: %#v", got)
	}
	if !got.MultiTenantOrganization.IsEnabled || got.MultiTenantOrganization.TenantsCount != 3 {
		t.Errorf("MTO mismatch: %#v", got.MultiTenantOrganization)
	}
}

func TestBuildCrossTenantAccessSummary_PartnersOnly(t *testing.T) {
	// Edge case: partners without a default. Microsoft Graph would never
	// return this in practice, but make sure the helper doesn't drop it.
	partners := []types.CrossTenantPartnerPolicy{{TenantID: "t-1"}}
	got := BuildCrossTenantAccessSummary(nil, partners, nil)
	if got == nil || len(got.Partners) != 1 || got.Default != nil {
		t.Errorf("partners-only mismatch: %#v", got)
	}
}
