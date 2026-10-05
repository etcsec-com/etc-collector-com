package settings

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestAZAdminPortalAccessOpen_Retired proves the false-positive detector no
// longer emits. AzureTenantConfig.AdminPortalAccess is never populated by the
// Azure provider - GetTenantConfig only reads SecurityDefaults,
// GuestInvitationPolicy and UserRegistrationAllowed off
// Policies().AuthorizationPolicy() - and "restrict access to the Microsoft
// Entra admin center" has no corresponding property anywhere in Microsoft
// Graph GA (msgraph-sdk-go@v1.94.0 models.AuthorizationPolicy). The detector
// therefore fired unconditionally on every tenant. RED on unpatched code:
// admin-portal-access-open.go's init() still calls audit.MustRegister, so
// Get() returns ok=true and this assertion fails.
func TestAZAdminPortalAccessOpen_Retired(t *testing.T) {
	if _, ok := audit.DefaultRegistry.Get("AZ_ADMIN_PORTAL_ACCESS_OPEN"); ok {
		t.Fatal("AZ_ADMIN_PORTAL_ACCESS_OPEN must not be registered: AdminPortalAccess is never collected by any Graph GA endpoint, so the detector can only guess")
	}
}
