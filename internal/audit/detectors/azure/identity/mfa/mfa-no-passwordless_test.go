package mfa

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestMfaNoPasswordless_FIDO2ScopedToOneGroupStillFlagged mirrors the
// MFA_NO_FIDO2 fix: a FIDO2 toggle that is "enabled" but scoped to a single
// group must not count as tenant-wide passwordless coverage.
func TestMfaNoPasswordless_FIDO2ScopedToOneGroupStillFlagged(t *testing.T) {
	d := NewMfaNoPasswordlessDetector()
	data := &audit.DetectorData{
		AzureAuthMethodsPolicy: &types.AuthMethodsPolicy{
			FIDO2: types.AuthMethodConfig{
				State: "enabled",
				IncludeTargets: []types.AuthMethodTarget{
					{TargetType: "group", ID: "some-pilot-group"},
				},
			},
		},
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 when FIDO2 is scoped to one group and Authenticator is off, got %d", f.Count)
	}
}

func TestMfaNoPasswordless_FIDO2AllUsersNotFlagged(t *testing.T) {
	d := NewMfaNoPasswordlessDetector()
	data := &audit.DetectorData{
		AzureAuthMethodsPolicy: &types.AuthMethodsPolicy{
			FIDO2: types.AuthMethodConfig{
				State:          "enabled",
				IncludeTargets: []types.AuthMethodTarget{{TargetType: "group", ID: "all_users"}},
			},
		},
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 when FIDO2 covers all_users, got %d", f.Count)
	}
}

// TestMfaNoPasswordless_DescriptionDisclosesAuthenticatorModeGap locks in
// the honest disclosure: Authenticator "enabled" is not proof of
// passwordless mode, because per-group authenticationMode is not collected.
func TestMfaNoPasswordless_DescriptionDisclosesAuthenticatorModeGap(t *testing.T) {
	d := NewMfaNoPasswordlessDetector()
	f := d.Detect(context.Background(), &audit.DetectorData{})[0]

	if !strings.Contains(f.Description, "not proof") && !strings.Contains(f.Description, "not currently collected") {
		t.Errorf("description must disclose that Authenticator mode is unconfirmed, got %q", f.Description)
	}
}
