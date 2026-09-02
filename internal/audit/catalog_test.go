// This test compares the generated catalog against the committed markdown.
//
// It used to be gated behind `-tags pro`, because a build without that tag
// produced a catalog missing the 26 Pro-only detectors. Since v3.2.0 there is
// a single edition and the gate is gone — every detector is always registered.
//
// The catalogs live at a different depth depending on the checkout: in the
// development repo the module sits under `public/`, in the published mirror it
// is the repo root. Resolve both rather than assume one — the hardcoded
// `../../../` silently worked in development and broke the published CI.
package audit_test

import (
	"os"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/catalog"

	// Side-effect imports — every detector subpackage registers with
	// audit.DefaultRegistry via init(). Without these blank imports the
	// registry is empty at test time and the regen would produce empty
	// catalogs (which would either fail to match or trivially match an
	// empty committed file — neither is useful).
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure"
)

// catalogVersion is the version label embedded into the generated header.
// Hardcoded here (must match cmd/etc-collector/main.go's Version) because
// this package is internal-only and doesn't import the cmd package.
// Doit suivre main.Version. C'est le TROISIEME endroit ou la version vit —
// avec cmd/etc-collector/main.go et l'en-tete des catalogues generes — et
// c'est ce qui a fait echouer la CI publique sur la v3.2.0.
const catalogVersion = "3.2.0"

// TestCatalogIsStable regenerates the AD and Azure vulnerability catalog
// markdowns from the live audit.DefaultRegistry and compares them to the
// committed files under docs/vulnerabilities/.
//
// Failure means a contributor changed a detector's title, description,
// severity, or set of registered detectors without re-running
// `make catalog`. The fix is always: `make catalog && git add
// docs/vulnerabilities/`.
//
// This test subsumes the older TestVulnerabilityCatalogInSync (which only
// checked detector ID presence) — now we verify the WHOLE markdown content
// (titles, descriptions, severities, source paths, ordering, counts).
//
// Build with -tags pro to include Pro-only detectors (ESC1-11, attack
// paths, Azure risk protection); without it the registry is missing those
// 26 IDs and the regen will diverge from the committed file. CI runs in pro.
func TestCatalogIsStable(t *testing.T) {
	cases := []struct {
		platform catalog.Platform
		path     string
	}{
		{catalog.PlatformAD, "docs/vulnerabilities/active-directory/AD_VULNERABILITY_CATALOG.md"},
		{catalog.PlatformAzure, "docs/vulnerabilities/azure/AZURE_VULNERABILITY_CATALOG.md"},
	}
	for _, tc := range cases {
		t.Run(string(tc.platform), func(t *testing.T) {
						var want []byte
			var err error
			var tried []string
			// `../../` = racine du miroir publie (internal/audit → racine).
			// `../../../` = racine du depot de developpement (le module vit
			// un niveau plus bas, sous public/).
			for _, prefix := range []string{"../../", "../../../"} {
				p := prefix + tc.path
				tried = append(tried, p)
				if want, err = os.ReadFile(p); err == nil {
					break
				}
			}
			if err != nil {
				t.Fatalf("catalog not found, tried %v: %v", tried, err)
			}
			got, err := catalog.Generate(audit.DefaultRegistry, tc.platform, catalogVersion)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			if string(want) == got {
				return
			}
			line := firstDiffLine(string(want), got)
			t.Fatalf("Catalog %s drifted from registry. Run `make catalog` and commit the result.\nFirst diff at line %d:\n  want: %q\n  got:  %q",
				tc.path, line, lineAt(string(want), line), lineAt(got, line))
		})
	}
}

func firstDiffLine(a, b string) int {
	la := strings.Split(a, "\n")
	lb := strings.Split(b, "\n")
	n := len(la)
	if len(lb) < n {
		n = len(lb)
	}
	for i := 0; i < n; i++ {
		if la[i] != lb[i] {
			return i + 1
		}
	}
	if len(la) != len(lb) {
		return n + 1
	}
	return 0
}

func lineAt(s string, n int) string {
	lines := strings.Split(s, "\n")
	if n <= 0 || n > len(lines) {
		return "<EOF>"
	}
	return lines[n-1]
}
