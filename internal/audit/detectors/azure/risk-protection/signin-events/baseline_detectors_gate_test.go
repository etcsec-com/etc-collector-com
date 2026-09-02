package signinevents

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/catalog"
)

// The T_019 provider gate keys off a detector's Go package path: anything under
// internal/audit/detectors/azure/ is Entra-only and must not run during an
// on-prem AD audit. These two are "absence-relative" detectors reading Entra
// sign-in logs — on an AD audit there are none, so without the gate they would
// be exactly the kind of noise T_019 removed.
//
// Asserting the classification here is cheaper and more direct than inferring
// it from an end-to-end audit: the gate's own test (internal/audit) enumerates
// the whole registry, but neither detector emits findings on empty data, so it
// would pass whether or not they were gated.
func TestBaselineDetectorsAreProviderGatedToAzure(t *testing.T) {
	for _, d := range []audit.Detector{
		NewSPSignInSpikeDetector(),
		NewUnusualGeoAdminDetector(),
	} {
		if got := catalog.PlatformOf(d); got != catalog.PlatformAzure {
			t.Errorf("%s classifies as platform %q, want %q — it would run during an on-prem AD audit",
				d.ID(), got, catalog.PlatformAzure)
		}
	}
}

// Both must be registered in the global registry, which is what makes them
// visible to `etc-collector audit list` and to the catalog generator.
func TestBaselineDetectorsAreRegistered(t *testing.T) {
	for _, id := range []string{RISK_SP_SIGNIN_SPIKE, RISK_UNUSUAL_GEO_ADMIN} {
		d, ok := audit.DefaultRegistry.Get(id)
		if !ok {
			t.Fatalf("%s is not registered", id)
		}
		if d.Category() != audit.CategoryRiskProtection {
			t.Errorf("%s category = %s, want %s", id, d.Category(), audit.CategoryRiskProtection)
		}
		if d.Doc().Title == "" {
			t.Errorf("%s has no catalog title — run `go run ./tools/cataloggen`", id)
		}
	}
}
