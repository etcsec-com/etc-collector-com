package security

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AZ_GROUP_UNIFIED_NO_EXPIRY was hard-coded to fire (count=1) on every run,
// regardless of tenant data, even though it could tell "no policy" from "a
// covering policy exists" from a single GET /groupLifecyclePolicies call.
// Confirms the fix reads real data instead.

func TestUnifiedGroupNoExpiry_InfoFindingWhenNotProbed(t *testing.T) {
	d := NewUnifiedGroupNoExpiryDetector()
	data := &audit.DetectorData{} // AzureTenantConfig nil - couldn't check

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (visible ignorance) when the policy endpoint was never probed, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityInfo {
		t.Fatalf("expected Info severity for an unprobed check, got %s", findings[0].Severity)
	}
}

func TestUnifiedGroupNoExpiry_SilentWhenTenantFullyGoverned(t *testing.T) {
	d := NewUnifiedGroupNoExpiryDetector()
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{
			GroupLifecyclePolicyExists:            boolPtr(true),
			GroupLifecyclePolicyManagedGroupTypes: "All",
		},
		Groups: []types.Group{
			{SAMAccountName: "M365-One", AzureGroupTypes: []string{"Unified"}},
			{SAMAccountName: "M365-Two", AzureGroupTypes: []string{"Unified"}},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected Count 0 when a covering (managedGroupTypes=All) policy exists, got %+v", findings)
	}
}

func TestUnifiedGroupNoExpiry_FiresWithNamedGroupsWhenNoPolicy(t *testing.T) {
	d := NewUnifiedGroupNoExpiryDetector()
	exists := false
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{
			GroupLifecyclePolicyExists: &exists,
		},
		Groups: []types.Group{
			{SAMAccountName: "M365-One", AzureGroupTypes: []string{"Unified"}},
			{SAMAccountName: "SG-NotUnified", AzureGroupTypes: []string{}},
		},
		IncludeDetails: true,
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected Count 1 (only the M365 group) when no policy exists, got %+v", findings)
	}
	if len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("expected the M365 group to be named in AffectedEntities, got %+v", findings[0].AffectedEntities)
	}
}

func TestUnifiedGroupNoExpiry_FiresWhenPolicyDoesNotCoverAll(t *testing.T) {
	d := NewUnifiedGroupNoExpiryDetector()
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{
			GroupLifecyclePolicyExists:            boolPtr(true),
			GroupLifecyclePolicyManagedGroupTypes: "Selected",
		},
		Groups: []types.Group{
			{SAMAccountName: "M365-One", AzureGroupTypes: []string{"Unified"}},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected Count 1 when the policy scope is 'Selected' (cannot prove this group is covered), got %+v", findings)
	}
}

func TestUnifiedGroupNoExpiry_SilentWhenNoPolicyButNoM365Groups(t *testing.T) {
	d := NewUnifiedGroupNoExpiryDetector()
	exists := false
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{
			GroupLifecyclePolicyExists: &exists,
		},
		Groups: []types.Group{
			{SAMAccountName: "SG-NotUnified", AzureGroupTypes: []string{}},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected Count 0 when there are no M365 groups to protect, got %+v", findings)
	}
}
