package hybrid

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// boolPtr is shared by the hybrid-*_test.go files in this package.
func boolPtr(b bool) *bool { return &b }

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
