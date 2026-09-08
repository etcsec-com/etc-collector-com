package access

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestAppAccess_NoPolicyProbed_NoVerdict(t *testing.T) {
	d := NewAppAccessUnrestrictedDetector()
	data := &audit.DetectorData{}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding when policy wasn't probed, got %+v", findings)
	}
}

func TestAppAccess_RestrictedGuestRole_NoFinding(t *testing.T) {
	d := NewAppAccessUnrestrictedDetector()
	data := &audit.DetectorData{
		AzureAuthorizationPolicy: &types.AuthorizationPolicy{
			GuestUserRoleID: "2af84b1e-32c8-42b7-82bc-daa82404023b", // Restricted Guest User
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for restricted guest role, got %d", f.Count)
	}
}

func TestAppAccess_UnrestrictedUserRole_Fires(t *testing.T) {
	d := NewAppAccessUnrestrictedDetector()
	data := &audit.DetectorData{
		AzureAuthorizationPolicy: &types.AuthorizationPolicy{
			GuestUserRoleID: types.AzureGuestRoleUnrestrictedUser,
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 when guests hold the User role, got %d", f.Count)
	}
}
