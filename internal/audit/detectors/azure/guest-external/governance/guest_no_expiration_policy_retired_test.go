package governance

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestGuestNoExpirationPolicy_Retired proves the detector no longer emits.
// The condition (guest account expiration/lifecycle policy) is only
// measurable via Microsoft Graph's externalIdentitiesPolicy
// (guestUserLifecycle / B2BManagementPolicy) - no field for it exists on
// audit.DetectorData, and no provider requests it (grep confirmed: zero
// hits for externalIdentitiesPolicy/B2BManagementPolicy across
// internal/providers/ and pkg/types/). RED on unpatched code:
// guest-no-expiration-policy.go's init() still calls audit.MustRegister, so
// Get() returns ok=true and this assertion fails.
func TestGuestNoExpirationPolicy_Retired(t *testing.T) {
	if _, ok := audit.DefaultRegistry.Get("GUEST_NO_EXPIRATION_POLICY"); ok {
		t.Fatal("GUEST_NO_EXPIRATION_POLICY must not be registered: no provider collects guest expiration/lifecycle policy data")
	}
}
