package hybrid

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestHybridOrphaned_DescriptionDoesNotClaimSyncFailure locks in the
// corrected framing: "disabled + synced" is a routine hygiene
// signal, not proof of a failed Azure AD Connect sync - no Microsoft source
// documents that state combination as a sync-failure signature, so the
// description must not assert a causal "Connect failed" story.
func TestHybridOrphaned_DescriptionDoesNotClaimSyncFailure(t *testing.T) {
	d := NewHybridOrphanedCloudUserDetector()
	f := d.Detect(context.Background(), &audit.DetectorData{})[0]

	if strings.Contains(f.Description, "Connect failed") {
		t.Errorf("description must not claim a proven Connect sync failure, got %q", f.Description)
	}
}

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
