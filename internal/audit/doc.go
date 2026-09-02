package audit

import "github.com/etcsec-com/etc-collector/pkg/types"

// DetectorDoc is the static, catalog-facing metadata of a detector. It is
// the source of truth for the vulnerability catalogs under
// docs/vulnerabilities/ — the markdown files there are regenerated from
// every Detector's Doc() return value via `make catalog`.
//
// Conventions:
//
//   - Title / Description are canonical prose with NO runtime placeholders.
//     Detectors that emit Sprintf-formatted Findings at runtime should still
//     return an abstract description here (e.g. "Trust password not rotated
//     recently", not "3 trust(s) have pwdLastSet older than 365 days").
//   - Severity is the WORST severity the detector can emit. Detectors with
//     conditional severity (e.g. ANSSI_R42_TRUST_PASSWORD_OLD escalating from
//     Medium to High at 730 days) report the worst case so the catalog
//     reflects the real risk profile.
//   - SourceFile is the path relative to internal/audit/detectors/, e.g.
//     "ad/compliance/anssi/r42_r43_password_rotation.go". Used as the "File"
//     column in the markdown catalogs.
type DetectorDoc struct {
	Title       string
	Description string
	Severity    types.Severity
	SourceFile  string
}

// Weight returns the scoring weight derived from Severity. Mirrors
// types.Severity.Weight() for ergonomics in templates.
func (d DetectorDoc) Weight() float64 {
	return d.Severity.Weight()
}
