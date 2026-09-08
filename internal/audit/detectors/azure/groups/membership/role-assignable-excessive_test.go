package membership

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func ptrTrue() *bool { v := true; return &v }

// TestRoleAssignable_AdminCountAloneDoesNotFire covers the repair of
// AZ_GROUP_ROLE_ASSIGNABLE: the detector used to read group.AdminCount, an AD
// attribute (AdminSDHolder protection) with no semantic link to Entra role
// assignability. AdminCount alone must not fire.
func TestRoleAssignable_AdminCountAloneDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{{DisplayName: "g1", AdminCount: true}},
	}
	f := NewRoleAssignableDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("AdminCount alone must not fire (no Entra role-assignability signal), got count=%d", f.Count)
	}
}

func TestRoleAssignable_AzureIsAssignableToRoleFires(t *testing.T) {
	data := &audit.DetectorData{
		Groups:         []types.Group{{DisplayName: "g1", AzureIsAssignableToRole: ptrTrue()}},
		IncludeDetails: true,
	}
	f := NewRoleAssignableDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 when AzureIsAssignableToRole is true, got count=%d", f.Count)
	}
}
