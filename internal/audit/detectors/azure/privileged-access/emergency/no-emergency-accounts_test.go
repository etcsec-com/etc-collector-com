package emergency

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestNoEmergencyAccounts_ServiceAccountExclusionDoesNotCount covers the
// source review finding: a tenant with no real break-glass accounts, but
// with a service account excluded from its all-users CA policy for an
// unrelated reason, was wrongly treated as having emergency accounts because
// the old logic only checked "any exclusion exists". Microsoft's documented
// pattern (security-emergency-access) is specific: permanent Global
// Administrator assignment, excluded from the blocking policy.
func TestNoEmergencyAccounts_ServiceAccountExclusionDoesNotCount(t *testing.T) {
	d := NewNoEmergencyAccountsDetector()
	data := &audit.DetectorData{
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{
				State:        "enabled",
				IncludeUsers: []string{"All"},
				ExcludeUsers: []string{"svc-backup-account"},
			},
		},
		// No Global Administrator assignments at all - no real break-glass accounts exist.
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 (no real emergency accounts despite an unrelated exclusion), got %d", f.Count)
	}
}

func TestNoEmergencyAccounts_TwoPermanentGlobalAdminsExcludedCountsAsPresent(t *testing.T) {
	d := NewNoEmergencyAccountsDetector()
	data := &audit.DetectorData{
		AzureRoleAssignments: []types.RoleAssignment{
			{PrincipalID: "breakglass1", RoleID: types.AzureRoleGlobalAdmin, IsPermanent: true},
			{PrincipalID: "breakglass2", RoleID: types.AzureRoleGlobalAdmin, IsPermanent: true},
		},
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{
				State:        "enabled",
				IncludeUsers: []string{"All"},
				ExcludeUsers: []string{"breakglass1", "breakglass2"},
			},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for two permanent Global Admins excluded from the all-users policy, got %d", f.Count)
	}
}

func TestNoEmergencyAccounts_OnlyOneExcludedStillFlags(t *testing.T) {
	d := NewNoEmergencyAccountsDetector()
	data := &audit.DetectorData{
		AzureRoleAssignments: []types.RoleAssignment{
			{PrincipalID: "breakglass1", RoleID: types.AzureRoleGlobalAdmin, IsPermanent: true},
		},
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{
				State:        "enabled",
				IncludeUsers: []string{"All"},
				ExcludeUsers: []string{"breakglass1"},
			},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 (Microsoft recommends two or more), got %d", f.Count)
	}
}

func TestNoEmergencyAccounts_EligibleGlobalAdminNotCountedAsBreakGlass(t *testing.T) {
	d := NewNoEmergencyAccountsDetector()
	data := &audit.DetectorData{
		AzureRoleAssignments: []types.RoleAssignment{
			{PrincipalID: "breakglass1", RoleID: types.AzureRoleGlobalAdmin, IsPermanent: true},
			{PrincipalID: "eligible-admin", RoleID: types.AzureRoleGlobalAdmin, IsPermanent: false, IsEligible: true},
		},
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{
				State:        "enabled",
				IncludeUsers: []string{"All"},
				ExcludeUsers: []string{"breakglass1", "eligible-admin"},
			},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1: a PIM-eligible assignment is not a permanent break-glass account, got %d", f.Count)
	}
}
