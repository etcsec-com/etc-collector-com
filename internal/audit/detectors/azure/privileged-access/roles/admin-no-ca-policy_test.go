package roles

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAdminNoCAPolicy_AllUsersMFABaselineCounts covers the gap the source
// review found: a tenant protecting admins through the generic "MFA for all
// users" Conditional Access baseline (IncludeUsers=All, no IncludeRoles) was
// wrongly flagged as having no admin protection at all, because the detector
// only recognized the role-scoped pattern. Microsoft documents both the
// role-scoped policy and the all-users MFA baseline as valid ways to satisfy
// this recommendation (see the source note on AdminNoCAPolicyDetector).
func TestAdminNoCAPolicy_AllUsersMFABaselineCounts(t *testing.T) {
	d := NewAdminNoCAPolicyDetector()
	data := &audit.DetectorData{
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{
				State:         "enabled",
				IncludeUsers:  []string{"All"},
				GrantControls: []string{"mfa"},
			},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 (all-users MFA baseline should count as admin protection), got %d", f.Count)
	}
}

func TestAdminNoCAPolicy_RoleScopedPolicyCounts(t *testing.T) {
	d := NewAdminNoCAPolicyDetector()
	data := &audit.DetectorData{
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{State: "enabled", IncludeRoles: []string{types.AzureRoleGlobalAdmin}},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for role-scoped policy, got %d", f.Count)
	}
}

func TestAdminNoCAPolicy_AllUsersWithoutMFADoesNotCount(t *testing.T) {
	d := NewAdminNoCAPolicyDetector()
	data := &audit.DetectorData{
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{
				State:         "enabled",
				IncludeUsers:  []string{"All"},
				GrantControls: []string{"compliantDevice"},
			},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 (all-users policy without MFA grant control is not admin protection), got %d", f.Count)
	}
}

func TestAdminNoCAPolicy_NoPolicyFlags(t *testing.T) {
	d := NewAdminNoCAPolicyDetector()
	data := &audit.DetectorData{}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 for no policies at all, got %d", f.Count)
	}
}
