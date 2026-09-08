package mfa

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestMfaNoFIDO2_EnabledButScopedToOneGroupStillFlagged reproduces the exact
// gap from: fido2.state=enabled tenant-wide, but includeTargets points
// to a single group rather than all_users. Before this fix, State alone
// made this pass as "FIDO2 is enabled" even though most users have no FIDO2
// coverage.
func TestMfaNoFIDO2_EnabledButScopedToOneGroupStillFlagged(t *testing.T) {
	d := NewMfaNoFido2Detector()
	data := &audit.DetectorData{
		AzureAuthMethodsPolicy: &types.AuthMethodsPolicy{
			FIDO2: types.AuthMethodConfig{
				State: "enabled",
				IncludeTargets: []types.AuthMethodTarget{
					{TargetType: "group", ID: "d0bef684-0000-0000-0000-000000000000"},
				},
			},
		},
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 (insufficient coverage) when FIDO2 is scoped to a single group, got %d", f.Count)
	}
}

func TestMfaNoFIDO2_EnabledForAllUsersNotFlagged(t *testing.T) {
	d := NewMfaNoFido2Detector()
	data := &audit.DetectorData{
		AzureAuthMethodsPolicy: &types.AuthMethodsPolicy{
			FIDO2: types.AuthMethodConfig{
				State: "enabled",
				IncludeTargets: []types.AuthMethodTarget{
					{TargetType: "group", ID: "all_users"},
				},
			},
		},
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 when FIDO2 covers all_users, got %d", f.Count)
	}
}

func TestMfaNoFIDO2_DisabledStateFlagged(t *testing.T) {
	d := NewMfaNoFido2Detector()
	data := &audit.DetectorData{
		AzureAuthMethodsPolicy: &types.AuthMethodsPolicy{
			FIDO2: types.AuthMethodConfig{State: "disabled"},
		},
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 when FIDO2 is disabled, got %d", f.Count)
	}
}
