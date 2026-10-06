package settings

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestUserConsentAllowAll_SilentWhenPolicyUnknown(t *testing.T) {
	d := NewUserConsentAllowAllDetector()
	data := &audit.DetectorData{AzureTenantConfig: &types.AzureTenantConfig{}}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected no verdict when consent policy is unmeasured (nil), got %+v", findings)
	}
}

func TestUserConsentAllowAll_SilentWhenDisabled(t *testing.T) {
	d := NewUserConsentAllowAllDetector()
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{UserConsentGrantPolicies: []string{}},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 when consent to apps is disabled (empty policy list), got %d", f.Count)
	}
}

func TestUserConsentAllowAll_SilentWhenLowRiskPolicy(t *testing.T) {
	d := NewUserConsentAllowAllDetector()
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{
			UserConsentGrantPolicies: []string{"ManagePermissionGrantsForSelf.microsoft-user-default-low"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for low-risk policy, got %d", f.Count)
	}
}

func TestUserConsentAllowAll_FiresWhenLegacyPolicy(t *testing.T) {
	d := NewUserConsentAllowAllDetector()
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{
			UserConsentGrantPolicies: []string{"ManagePermissionGrantsForSelf.microsoft-user-default-legacy"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 when the unrestricted built-in policy is assigned, got %d", f.Count)
	}
}
