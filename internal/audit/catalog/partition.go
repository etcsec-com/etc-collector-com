// Package catalog renders the vulnerability catalog markdown files
// (docs/vulnerabilities/{active-directory,azure}/*.md) from the runtime
// detector registry. It is the single source of truth for catalog content;
// `make catalog` invokes Generate(...) which iterates DefaultRegistry and
// writes the markdown files. CI verifies the committed files match the
// regenerated output via TestCatalogIsStable.
package catalog

import (
	"reflect"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// Platform identifies which markdown catalog a detector belongs to.
type Platform string

const (
	PlatformAD      Platform = "ad"
	PlatformAzure   Platform = "azure"
	PlatformOther   Platform = "other" // intune, exchange, google, ...
	PlatformUnknown Platform = "unknown"
)

// PlatformOf classifies a detector by inspecting its Go package path. We
// rely on the convention that detectors live under
// `internal/audit/detectors/<platform>/...`.
//
// Returns PlatformUnknown for anything that doesn't fit the convention
// (catalog generator filters those out — they won't appear in either
// markdown file).
func PlatformOf(d audit.Detector) Platform {
	pkg := reflect.TypeOf(d).Elem().PkgPath()
	const prefix = "github.com/etcsec-com/etc-collector/internal/audit/detectors/"
	rest := strings.TrimPrefix(pkg, prefix)
	if rest == pkg { // prefix not present
		return PlatformUnknown
	}
	switch first(rest) {
	case "ad":
		return PlatformAD
	case "azure":
		return PlatformAzure
	case "intune", "exchange", "google":
		return PlatformOther
	}
	return PlatformUnknown
}

func first(p string) string {
	if i := strings.IndexByte(p, '/'); i > 0 {
		return p[:i]
	}
	return p
}
