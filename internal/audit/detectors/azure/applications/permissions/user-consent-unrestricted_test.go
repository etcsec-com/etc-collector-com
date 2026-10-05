package permissions

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestUserConsentUnrestricted_NilConfig_NoVerdict(t *testing.T) {
	d := NewUserConsentUnrestrictedDetector()
	f := d.Detect(context.Background(), &audit.DetectorData{})[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 when AzureTenantConfig is nil, got %d", f.Count)
	}
}

func TestUserConsentUnrestricted_PoliciesUnread_NoGuess(t *testing.T) {
	d := NewUserConsentUnrestrictedDetector()
	data := &audit.DetectorData{
		// UserConsentGrantPolicies left nil: Graph call failed/was skipped.
		// This is the state the field is ALWAYS in today, on every real tenant,
		// because the provider never assigns it -- reproducing the bug: on
		// today's code this used to always fire (Count=1) since the old check
		// was UserConsentPolicy == "".
		AzureTenantConfig: &types.AzureTenantConfig{},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 when policy could not be read (no data => no verdict), got %d", f.Count)
	}
}

func TestUserConsentUnrestricted_ConsentDisabled_NotFlagged(t *testing.T) {
	d := NewUserConsentUnrestrictedDetector()
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{
			UserConsentGrantPolicies: []string{}, // non-nil empty: consent to apps disabled
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 when user consent to apps is disabled, got %d", f.Count)
	}
}

func TestUserConsentUnrestricted_LowRiskPolicy_NotFlagged(t *testing.T) {
	d := NewUserConsentUnrestrictedDetector()
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{
			UserConsentGrantPolicies: []string{"ManagePermissionGrantsForSelf.microsoft-user-default-low"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for low-risk/verified-publisher policy, got %d", f.Count)
	}
}

func TestUserConsentUnrestricted_LegacyPolicy_Flagged(t *testing.T) {
	d := NewUserConsentUnrestrictedDetector()
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
