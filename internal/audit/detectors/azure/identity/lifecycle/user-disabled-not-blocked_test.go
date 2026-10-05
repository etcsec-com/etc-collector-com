package lifecycle

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestUserDisabledNotBlocked_TitleDoesNotClaimSignInWorks reproduces the
// ecart: disabling a user (accountEnabled=false) blocks new sign-in
// immediately (Microsoft Learn, "Revoke user access in an emergency in
// Microsoft Entra ID"). The old title, "Disabled Users Not Blocked from
// Sign-In", asserted the opposite of what Microsoft documents. What this
// detector can actually measure - because signInSessionsValidFromDateTime
// isn't collected - is that session/token revocation status is unconfirmed,
// not that sign-in itself still works.
func TestUserDisabledNotBlocked_TitleDoesNotClaimSignInWorks(t *testing.T) {
	d := NewUserDisabledNotBlockedDetector()
	data := &audit.DetectorData{
		Users: []types.User{
			{DisplayName: "disabled-user", Disabled: true},
		},
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 disabled user flagged, got %d", f.Count)
	}
	if strings.Contains(f.Title, "Not Blocked from Sign-In") {
		t.Errorf("title must not claim sign-in still works after disable (Microsoft Entra blocks new sign-in immediately on disable): got %q", f.Title)
	}
	if strings.Contains(f.Description, "may still have active sessions or tokens") && !strings.Contains(f.Description, "revoke") {
		t.Errorf("description must explain the actual gap (unconfirmed session revocation), got %q", f.Description)
	}
}
