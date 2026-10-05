package membership

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestPrivilegedChanges_AzureRoleAssignableGroup_Detected reproduces the bug
// reported against Azure data: a role-assignable Entra group (the Graph
// analogue of AD's AdminCount) must fire the detector even though
// group.AdminCount is never set by the Azure provider.
func TestPrivilegedChanges_AzureRoleAssignableGroup_Detected(t *testing.T) {
	d := NewPrivilegedChangesDetector()
	assignable := true
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Tier0-Admins", AzureIsAssignableToRole: &assignable},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 (Azure role-assignable group must count as privileged), got %d", f.Count)
	}
}

// TestPrivilegedChanges_NoPrivilegedGroups_NotFlagged guards against the
// opposite regression: an ordinary Azure group (not role-assignable, no
// AdminCount) must not falsely light up the detector.
func TestPrivilegedChanges_NoPrivilegedGroups_NotFlagged(t *testing.T) {
	d := NewPrivilegedChangesDetector()
	notAssignable := false
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "All-Employees", AzureIsAssignableToRole: &notAssignable},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0, got %d", f.Count)
	}
}
