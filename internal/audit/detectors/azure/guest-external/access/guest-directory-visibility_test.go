package access

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// The fiche for this detector proposed treating guestUserRoleId
// "10dae51f-b6af-4016-8d66-8c2a99b929b3" as the "unrestricted" signal, but
// that GUID is Microsoft's DEFAULT/LIMITED guest role, not the member-equivalent
// one - using it would make this detector fire on every untouched tenant
// (guaranteed false positive on the Microsoft-recommended default). The real
// "guests get member-level access" GUID is types.AzureGuestRoleUnrestrictedUser
// ("a0b1b346-4d3e-4e8b-98f8-753987be4970"), the same value
// GUEST_APP_ACCESS_UNRESTRICTED uses - confirmed against azadvertizer.net's
// Entra role template reference, independent of the fiche.

func TestDirectoryVisibility_NoPolicyData_NoFinding(t *testing.T) {
	d := NewDirectoryVisibilityDetector()
	data := &audit.DetectorData{}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 when authorizationPolicy wasn't collected, got %d", f.Count)
	}
}

func TestDirectoryVisibility_RestrictedGuestRole_NoFinding(t *testing.T) {
	d := NewDirectoryVisibilityDetector()
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

// TestDirectoryVisibility_DefaultLimitedGuestRole_NoFinding is the case that
// proves the fiche's proposed GUID would have been wrong: the DEFAULT/LIMITED
// guest role must NOT fire (it is Microsoft's own recommended baseline).
func TestDirectoryVisibility_DefaultLimitedGuestRole_NoFinding(t *testing.T) {
	d := NewDirectoryVisibilityDetector()
	data := &audit.DetectorData{
		AzureAuthorizationPolicy: &types.AuthorizationPolicy{
			GuestUserRoleID: "10dae51f-b6af-4016-8d66-8c2a99b929b3", // "Limited access (default)"
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for the default/limited guest role (not unrestricted), got %d", f.Count)
	}
}

func TestDirectoryVisibility_UnrestrictedGuestRole_Finding(t *testing.T) {
	d := NewDirectoryVisibilityDetector()
	data := &audit.DetectorData{
		AzureAuthorizationPolicy: &types.AuthorizationPolicy{
			GuestUserRoleID: types.AzureGuestRoleUnrestrictedUser, // "Same access as members"
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 for unrestricted (member-equivalent) guest role, got %d", f.Count)
	}
}
