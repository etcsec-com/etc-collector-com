package authmethods

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestWeakDefault_TitleDoesNotClaimObservedDefault locks in the corrected
// title/description: Microsoft Graph's authenticationMethodsPolicy has no
// "default method" property, so this must not claim to have observed one -
// only that SMS/voice is enabled while stronger methods are not.
func TestWeakDefault_TitleDoesNotClaimObservedDefault(t *testing.T) {
	d := NewWeakDefaultMethodDetector()
	data := &audit.DetectorData{
		AzureAuthMethodsPolicy: &types.AuthMethodsPolicy{
			SMS: types.AuthMethodConfig{State: "enabled"},
		},
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected count 1 when only SMS is enabled, got %d", f.Count)
	}
	if strings.Contains(strings.ToLower(f.Title), "default") {
		t.Errorf("title must not claim to observe a 'default' method that Graph does not expose, got %q", f.Title)
	}
}

func TestWeakDefault_NotFlaggedWhenAuthenticatorEnabled(t *testing.T) {
	d := NewWeakDefaultMethodDetector()
	data := &audit.DetectorData{
		AzureAuthMethodsPolicy: &types.AuthMethodsPolicy{
			SMS:                    types.AuthMethodConfig{State: "enabled"},
			MicrosoftAuthenticator: types.AuthMethodConfig{State: "enabled"},
		},
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected count 0 when Authenticator is also enabled, got %d", f.Count)
	}
}
