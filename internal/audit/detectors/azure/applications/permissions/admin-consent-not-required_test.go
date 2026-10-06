package permissions

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestAdminConsentNotRequired_NilConfig(t *testing.T) {
	d := NewAdminConsentNotRequiredDetector()
	f := d.Detect(context.Background(), &audit.DetectorData{})[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 with nil config, got %d", f.Count)
	}
}

func TestAdminConsentNotRequired_PoliciesUnread_NoVerdict(t *testing.T) {
	d := NewAdminConsentNotRequiredDetector()
	data := &audit.DetectorData{AzureTenantConfig: &types.AzureTenantConfig{}}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 when policy could not be read (nil => no verdict), got %d", f.Count)
	}
}

func TestAdminConsentNotRequired_LegacyPolicyFires(t *testing.T) {
	d := NewAdminConsentNotRequiredDetector()
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{
			UserConsentGrantPolicies: []string{"ManagePermissionGrantsForSelf.microsoft-user-default-legacy"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 with legacy policy assigned, got %d", f.Count)
	}
}

func TestAdminConsentNotRequired_LowPolicyDoesNotFire(t *testing.T) {
	d := NewAdminConsentNotRequiredDetector()
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{
			UserConsentGrantPolicies: []string{"ManagePermissionGrantsForSelf.microsoft-user-default-low"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 with low-impact-only policy, got %d", f.Count)
	}
}

func TestAdminConsentNotRequired_EmptyPoliciesDoesNotFire(t *testing.T) {
	d := NewAdminConsentNotRequiredDetector()
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{UserConsentGrantPolicies: []string{}},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 with consent disabled (empty policy list), got %d", f.Count)
	}
}
