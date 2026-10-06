package passwordpolicy

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestPasswordPolicyWeak_Retired verifies PASSWORD_POLICY_WEAK no longer
// emits: AzureTenantConfig carries no password-complexity field (Azure AD
// cloud-only tenants don't expose one via Graph at all), so the old "tenant
// reachable => Count=1" logic was a guess, not a measurement. The two
// mesurable facets (expiration, banned-password-list/protection) are
// already covered by ExpirationDetector, ProtectionDetector and
// BannedPasswordsDetector in this same package.
func TestPasswordPolicyWeak_Retired(t *testing.T) {
	if _, ok := audit.DefaultRegistry.Get("PASSWORD_POLICY_WEAK"); ok {
		t.Fatal("PASSWORD_POLICY_WEAK is still registered: it guesses from tenant reachability alone (no password field is collected) and must be retired")
	}
}
