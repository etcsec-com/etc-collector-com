// Package compliance_test (external test package, not internal `compliance`)
// on purpose: this test needs both the compliance package (for
// AllMappedDetectors) and the full detector registry (internal/audit, plus
// every detector package that registers into it via init()). internal/audit
// already imports internal/audit/compliance (engine.go, profiles.go) - an
// internal `package compliance` test file importing internal/audit back
// would be a genuine import cycle. The external test package sits outside
// that graph, so it can import both sides without one.
package compliance_test

import (
	"sort"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/compliance"

	// Side-effect imports - every detector subpackage registers with
	// audit.DefaultRegistry via init(). Without these blank imports the
	// registry would be empty at test time and every cited ID would look
	// orphaned, which is not what this test is checking.
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure"
)

// TestEveryMappingDetectorExistsInRegistry is the symmetric counterpart of
// TestEveryMappingControlExistsInCatalog (mappings_validation_test.go): that
// test verifies the CONTROL side of a citation (does the cited framework
// control exist in its catalog); this one verifies the DETECTOR side (does
// the cited detector ID correspond to a detector actually registered).
//
// Before this test existed, mappings.go could cite a detector ID that was
// never defined (or misspelled) anywhere, and nothing would say so - the
// citation would just sit there, permanently unable to produce a finding,
// so its control silently stays not_applicable forever. This check found three:
// AD_RECYCLE_BIN_DISABLED, NO_OFFLINE_BACKUP, and NO_HONEYPOT_ACCOUNT
// (missing the trailing S the real detector has).
//
// Checking against audit.DefaultRegistry rather than grepping source for the
// ID string also catches a detector that's DEFINED but never REGISTERED
// (its init() never called, or never imported) - the same class of bug as
// ESC4 once had (a commented-out init()), which a source grep would miss but the
// live registry correctly reports as absent.
func TestEveryMappingDetectorExistsInRegistry(t *testing.T) {
	var missing []string
	for _, id := range compliance.AllMappedDetectors() {
		if _, ok := audit.DefaultRegistry.Get(id); !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("mappings.go cites %d detector ID(s) with no matching entry in audit.DefaultRegistry: %v", len(missing), missing)
	}
}
