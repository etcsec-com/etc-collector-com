package mfa

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestMfaNotEnforcedAdmins_NonPrivilegedRoleDoesNotMaskGap reproduces the
// false negative fixed here: a CA policy targeting some role outside
// the isPrivileged set (any arbitrary role ID not in privilegedRoleIDs, e.g.
// a non-privileged built-in admin role) used to satisfy the old "any role"
// check and wrongly hide a real MFA gap on actually-privileged roles.
func TestMfaNotEnforcedAdmins_NonPrivilegedRoleDoesNotMaskGap(t *testing.T) {
	d := NewMfaNotEnforcedAdminsDetector()
	data := &audit.DetectorData{
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{
				State:         "enabled",
				IncludeRoles:  []string{"00000000-0000-0000-0000-000000000001"}, // arbitrary non-privileged role ID
				GrantControls: []string{"mfa"},
			},
		},
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 (gap not masked) when only a non-privileged role is targeted, got %d", f.Count)
	}
}

func TestMfaNotEnforcedAdmins_PrivilegedRoleWithMFASatisfies(t *testing.T) {
	d := NewMfaNotEnforcedAdminsDetector()
	data := &audit.DetectorData{
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{
				State:         "enabled",
				IncludeRoles:  []string{types.AzureRoleGlobalAdmin},
				GrantControls: []string{"mfa"},
			},
		},
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 when a privileged role requires mfa, got %d", f.Count)
	}
}
