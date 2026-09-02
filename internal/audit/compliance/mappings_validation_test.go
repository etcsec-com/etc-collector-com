package compliance

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit/compliance/catalogs"
)

// TestEveryMappingControlExistsInCatalog enforces that every Control code
// referenced by the mappings table exists in the corresponding framework's
// catalog. This is the single mechanical safeguard that prevents drift
// between mappings.go and the catalogs/ source of truth.
//
// If this test fails, either:
//  1. The mapping references a wrong code (typo, outdated internal R-code) —
//     fix the mapping to use the official code.
//  2. The catalog is missing a control — add it to the catalog file with
//     its official title and Section.
func TestEveryMappingControlExistsInCatalog(t *testing.T) {
	missing := map[string][]string{} // framework -> missing codes
	for detectorID, ms := range mappings {
		for _, m := range ms {
			if !catalogs.HasControl(m.Framework, m.Control) {
				key := m.Framework + ":" + m.Control
				missing[key] = append(missing[key], detectorID)
			}
		}
	}
	if len(missing) > 0 {
		for k, ids := range missing {
			t.Errorf("control %s not found in catalog (referenced by detectors: %v)", k, ids)
		}
	}
}
