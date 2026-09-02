package compliance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoHeuristicMarkersInANSSIDetectors enforces the v3.1.18 contract: no
// ANSSI detector under internal/audit/detectors/ad/compliance/anssi/ may
// contain a `// HEURISTIC` or `// FALSE_POSITIVE_RISK` marker.
//
// Markers are a deliberate signal devs leave when they implement a detector
// using a fragile proxy (display-name match, GPO count threshold, etc.).
// v3.1.18 eliminated the last such markers; future commits that reintroduce
// one fail this test, forcing a deliberate decision (either fix the proxy
// or accept the limitation explicitly via a comment marked
// `// HEURISTIC_ACCEPTED:` followed by a justification).
func TestNoHeuristicMarkersInANSSIDetectors(t *testing.T) {
	root := "../../audit/detectors/ad/compliance/anssi"
	bannedMarkers := []string{
		"// HEURISTIC ",
		"// HEURISTIC\n",
		"// HEURISTIC:",
		"// FALSE_POSITIVE_RISK",
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		text := string(data)
		// Allow explicit opt-in via "HEURISTIC_ACCEPTED:".
		stripped := strings.ReplaceAll(text, "HEURISTIC_ACCEPTED:", "X_X_X")
		for _, marker := range bannedMarkers {
			if strings.Contains(stripped, marker) {
				t.Errorf("%s contains banned marker %q — replace heuristic with real parsing or document with HEURISTIC_ACCEPTED:", path, marker)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
