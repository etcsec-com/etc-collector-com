// Package catalog renders the vulnerability catalog markdown files
// (docs/vulnerabilities/{active-directory,azure,exchange,intune,google}/*.md)
// from the runtime detector registry. It is the single source of truth for
// catalog content; `make catalog` invokes Generate(...) which iterates
// DefaultRegistry and writes the markdown files. CI verifies the committed
// files match the regenerated output via TestCatalogIsStable.
package catalog

import (
	"reflect"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// Platform identifies which markdown catalog a detector belongs to.
type Platform string

const (
	PlatformAD       Platform = "ad"
	PlatformAzure    Platform = "azure"
	PlatformExchange Platform = "exchange"
	PlatformIntune   Platform = "intune"
	PlatformGoogle   Platform = "google"
	PlatformUnknown  Platform = "unknown"
)

// AllPlatforms lists every platform that produces a generated catalog, in
// display order. This is the single source of truth for what --platform
// accepts and what `make catalog` regenerates - callers must build any
// user-facing list of platforms from this slice rather than hardcoding one,
// so adding a platform here is enough to keep them correct.
var AllPlatforms = []Platform{
	PlatformAD, PlatformAzure, PlatformExchange, PlatformIntune, PlatformGoogle,
}

// PlatformOf classifies a detector by inspecting its Go package path. We
// rely on the convention that detectors live under
// `internal/audit/detectors/<platform>/...`.
//
// Returns PlatformUnknown for anything that doesn't fit the convention
// (catalog generator filters those out - they won't appear in any markdown
// file).
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
	case "exchange":
		return PlatformExchange
	case "intune":
		return PlatformIntune
	case "google":
		return PlatformGoogle
	}
	return PlatformUnknown
}

func first(p string) string {
	if i := strings.IndexByte(p, '/'); i > 0 {
		return p[:i]
	}
	return p
}
