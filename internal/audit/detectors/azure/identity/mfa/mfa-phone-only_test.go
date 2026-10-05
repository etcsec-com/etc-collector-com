package mfa

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// MFA_PHONE_ONLY - the finding's self-description must be clear that
// this evaluates the tenant-wide authentication methods POLICY, not any
// specific user's actually-registered methods (the literal title previously
// read as a per-user claim it doesn't make).
func TestMfaPhoneOnly_TitleClarifiesTenantPolicyScope(t *testing.T) {
	d := NewMfaPhoneOnlyDetector()
	data := &audit.DetectorData{
		AzureAuthMethodsPolicy: &types.AuthMethodsPolicy{
			SMS:                    types.AuthMethodConfig{State: "enabled"},
			MicrosoftAuthenticator: types.AuthMethodConfig{State: "disabled"},
			FIDO2:                  types.AuthMethodConfig{State: "disabled"},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if !strings.Contains(strings.ToLower(findings[0].Title), "tenant") && !strings.Contains(strings.ToLower(findings[0].Title), "policy") {
		t.Fatalf("title must clarify this is a tenant-wide policy check, got %q", findings[0].Title)
	}
	if !strings.Contains(findings[0].Description, "tenant-wide") {
		t.Fatalf("description must say this evaluates the tenant-wide policy, not a specific user, got %q", findings[0].Description)
	}
	if findings[0].Count != 1 {
		t.Fatalf("phone-only-enabled policy must still be flagged, got Count=%d", findings[0].Count)
	}
}
