package hybrid

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestHybridCloudOnlyPriv_CloudOnlyGAIgnored locks in the corrected
// direction: a cloud-only privileged account is the
// Microsoft-recommended state (learn.microsoft.com/en-us/entra/identity/
// role-based-access-control/security-planning), not a finding.
func TestHybridCloudOnlyPriv_CloudOnlyGAIgnored(t *testing.T) {
	d := NewHybridCloudOnlyPrivilegedDetector()
	data := &audit.DetectorData{
		Users: []types.User{{
			ObjectSID:                  "user-1",
			AzureOnPremisesSyncEnabled: boolPtr(true),
		}},
		AzureRoleAssignments: []types.RoleAssignment{
			{RoleID: types.AzureRoleGlobalAdmin, PrincipalID: "user-2", PrincipalType: "User"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for cloud-only GA (now the recommended state), got %d", f.Count)
	}
}

// TestHybridCloudOnlyPriv_HybridSyncedGAFlagged locks in the corrected
// direction: an on-prem-synced account in a privileged role is the real
// risk per Microsoft guidance, and must now be flagged.
func TestHybridCloudOnlyPriv_HybridSyncedGAFlagged(t *testing.T) {
	d := NewHybridCloudOnlyPrivilegedDetector()
	data := &audit.DetectorData{
		Users: []types.User{{
			ObjectSID:                  "user-1",
			AzureOnPremisesSyncEnabled: boolPtr(true),
		}},
		AzureRoleAssignments: []types.RoleAssignment{
			{RoleID: types.AzureRoleGlobalAdmin, PrincipalID: "user-1", PrincipalType: "User"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 for hybrid-synced GA (now the flagged risk), got %d", f.Count)
	}
}

func TestHybridCloudOnlyPriv_ServicePrincipalIgnored(t *testing.T) {
	d := NewHybridCloudOnlyPrivilegedDetector()
	data := &audit.DetectorData{
		AzureRoleAssignments: []types.RoleAssignment{
			{RoleID: types.AzureRoleGlobalAdmin, PrincipalID: "sp-1", PrincipalType: "ServicePrincipal"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for SP principal, got %d", f.Count)
	}
}
