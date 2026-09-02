package hybrid

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func boolPtr(b bool) *bool { return &b }

func TestHybridOrphaned_SyncedEnabledUserIgnored(t *testing.T) {
	d := NewHybridOrphanedCloudUserDetector()
	data := &audit.DetectorData{
		Users: []types.User{{
			UserPrincipalName:          "a@t",
			AzureOnPremisesSyncEnabled: boolPtr(true),
			AzureAccountEnabled:        boolPtr(true),
		}},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for healthy synced user, got %d", f.Count)
	}
}

func TestHybridOrphaned_SyncedDisabledUserFlagged(t *testing.T) {
	d := NewHybridOrphanedCloudUserDetector()
	data := &audit.DetectorData{
		Users: []types.User{{
			UserPrincipalName:          "a@t",
			AzureOnPremisesSyncEnabled: boolPtr(true),
			AzureAccountEnabled:        boolPtr(false),
		}},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 for synced+disabled user, got %d", f.Count)
	}
}

func TestHybridOrphaned_CloudOnlyDisabledIgnored(t *testing.T) {
	d := NewHybridOrphanedCloudUserDetector()
	data := &audit.DetectorData{
		Users: []types.User{{
			UserPrincipalName:   "a@t",
			AzureAccountEnabled: boolPtr(false),
		}},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for cloud-only disabled user, got %d", f.Count)
	}
}

func TestHybridCloudOnlyPriv_HybridGAIgnored(t *testing.T) {
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
	if f.Count != 0 {
		t.Fatalf("expected 0 for hybrid GA, got %d", f.Count)
	}
}

func TestHybridCloudOnlyPriv_CloudOnlyGAFlagged(t *testing.T) {
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
	if f.Count != 1 {
		t.Fatalf("expected 1 for cloud-only GA, got %d", f.Count)
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
