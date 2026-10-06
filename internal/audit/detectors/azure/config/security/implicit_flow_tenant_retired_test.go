package security

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestAZImplicitFlowTenant_Retired proves the detector no longer emits.
// Microsoft Graph exposes "implicit grant" only at the app-registration
// level (web.implicitGrantSettings, already collected as
// types.Application.ImplicitGrantEnabled and correctly detected by
// APP_IMPLICIT_GRANT_ENABLED) - there is no tenant-wide equivalent in
// AzureTenantConfig or anywhere else collected. Detect() never read any
// field of data and fixed Count:1 unconditionally. RED on unpatched code:
// implicit-flow-enabled-tenant.go's init() still calls audit.MustRegister,
// so Get() returns ok=true and this assertion fails.
func TestAZImplicitFlowTenant_Retired(t *testing.T) {
	if _, ok := audit.DefaultRegistry.Get("AZ_IMPLICIT_FLOW_TENANT"); ok {
		t.Fatal("AZ_IMPLICIT_FLOW_TENANT must not be registered: no tenant-wide Graph signal exists (implicit grant is app-registration-level, already covered by APP_IMPLICIT_GRANT_ENABLED)")
	}
}
