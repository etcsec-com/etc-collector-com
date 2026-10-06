package security

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func boolPtr(b bool) *bool { return &b }
func intPtr(i int) *int    { return &i }

// AZ_GROUP_GUEST_IN_SECURITY was hard-coded to fire (count=1) on every run,
// regardless of tenant data, even though the provider already collects
// AzureExternalMembersCount per group. Confirms the fix reads real data.
func TestGuestInSecurityGroup_SilentWhenNoTenantHasGuestsInSecurityGroups(t *testing.T) {
	d := NewGuestInSecurityGroupDetector()
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "SG-NoGuests", AzureSecurityEnabled: boolPtr(true), AzureExternalMembersCount: intPtr(0)},
			{SAMAccountName: "M365-Unified", AzureSecurityEnabled: boolPtr(false), AzureExternalMembersCount: intPtr(3)},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding struct, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count 0 when no security group has guest members, got %d", findings[0].Count)
	}
}

func TestGuestInSecurityGroup_FiresOnlyForSecurityGroupsWithGuests(t *testing.T) {
	d := NewGuestInSecurityGroupDetector()
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "SG-WithGuests", AzureSecurityEnabled: boolPtr(true), AzureExternalMembersCount: intPtr(2)},
			{SAMAccountName: "SG-Clean", AzureSecurityEnabled: boolPtr(true), AzureExternalMembersCount: intPtr(0)},
			{SAMAccountName: "M365-WithGuests", AzureSecurityEnabled: boolPtr(false), AzureExternalMembersCount: intPtr(5)},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected Count 1 (only the security group with guests), got %+v", findings)
	}
}
