package membership

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestNestedPrivileged_AzureRoleAssignableGroup covers the repair of
// AZ_GROUP_NESTED_PRIVILEGED: convertAzureGroup never assigns AdminCount
// (an AD-only attribute) nor MemberOf for Azure-sourced groups, so the old
// `group.AdminCount && len(group.MemberOf) > 0` condition was structurally
// false on every Azure run. AzureIsAssignableToRole is the real Entra signal.
func TestNestedPrivileged_AzureRoleAssignableGroup(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DisplayName: "g1", AzureIsAssignableToRole: ptrTrue(), MemberOf: []string{"parent-1"}},
		},
		IncludeDetails: true,
	}
	f := NewNestedPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("role-assignable group nested in another group must fire, got count=%d", f.Count)
	}
}

func TestNestedPrivileged_NotNestedDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DisplayName: "g1", AzureIsAssignableToRole: ptrTrue()}, // no MemberOf: not nested
		},
	}
	f := NewNestedPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("a privileged group not nested anywhere must not fire, got count=%d", f.Count)
	}
}

func TestNestedPrivileged_AdminCountAloneStillWorks(t *testing.T) {
	// AD-sourced groups still use AdminCount; this leg must not regress.
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DisplayName: "g1", AdminCount: true, MemberOf: []string{"parent-1"}},
		},
	}
	f := NewNestedPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("AD AdminCount+MemberOf must still fire, got count=%d", f.Count)
	}
}
