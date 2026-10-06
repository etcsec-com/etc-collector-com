package access

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestAdminRoleDetector_NoData(t *testing.T) {
	d := NewAdminRoleDetector()
	data := &audit.DetectorData{}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 with no data, got %d", f.Count)
	}
}

func TestAdminRoleDetector_MemberAdmin_NotFlagged(t *testing.T) {
	d := NewAdminRoleDetector()
	data := &audit.DetectorData{
		Users: []types.User{
			{UserPrincipalName: "alice@contoso.com", AzureUserType: strPtrGuest("Member")},
		},
		AzureRoleAssignments: []types.RoleAssignment{
			{PrincipalName: "Alice Smith", UserPrincipalName: "alice@contoso.com", RoleName: "Global Administrator"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("a Member admin must not be flagged, got %d", f.Count)
	}
}

// TestAdminRoleDetector_GuestAdmin_Flagged proves the join works even when
// PrincipalName is a display name that differs from the UPN - the exact bug
// the re-review caught (joining on PrincipalName instead of UserPrincipalName).
func TestAdminRoleDetector_GuestAdmin_Flagged(t *testing.T) {
	d := NewAdminRoleDetector()
	data := &audit.DetectorData{
		Users: []types.User{
			{UserPrincipalName: "bob_partner.com#EXT#@contoso.onmicrosoft.com", AzureUserType: strPtrGuest("Guest")},
		},
		AzureRoleAssignments: []types.RoleAssignment{
			{
				PrincipalName:     "Bob External (Guest)", // display name, deliberately NOT the UPN
				UserPrincipalName: "bob_partner.com#EXT#@contoso.onmicrosoft.com",
				RoleName:          "Global Administrator",
			},
		},
		IncludeDetails: true,
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected 1 guest admin flagged, got %+v", findings)
	}
	if len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("expected 1 affected entity, got %d", len(findings[0].AffectedEntities))
	}
}

func strPtrGuest(s string) *string { return &s }
