package settings

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestAZLinkedInSyncEnabled_Retired proves the detector no longer emits.
// AzureTenantConfig.LinkedInSyncEnabled was never assigned by any provider:
// the LinkedIn-sync toggle lives on a distinct Graph resource
// (directorySetting/settingTemplate) that GetTenantConfig never calls - not
// a missing sibling field on an already-queried endpoint. The exact
// settingTemplate/key mapping isn't verifiable without a lab tenant, so
// rather than guess it, the detector is retired. RED on unpatched code:
// linkedin-sync-enabled.go's init() still calls audit.MustRegister, so
// Get() returns ok=true and this assertion fails.
func TestAZLinkedInSyncEnabled_Retired(t *testing.T) {
	if _, ok := audit.DefaultRegistry.Get("AZ_LINKEDIN_SYNC_ENABLED"); ok {
		t.Fatal("AZ_LINKEDIN_SYNC_ENABLED must not be registered: no provider ever collects the underlying directorySetting")
	}
}
