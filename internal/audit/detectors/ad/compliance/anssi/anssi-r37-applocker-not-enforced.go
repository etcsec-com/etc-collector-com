package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- AppLocker / WDAC heuristic (real control: PA-099 R11, p.28) ---
//
// The detector ID below ("R37") is a legacy internal label predating the
// v3.1.14 remap to official PA-099 R-codes (see mappings.go's package doc,
// and its migration note: "Re-mapped in v3.1.14 to use OFFICIAL ANSSI-PA-099
// v1.0 R-codes ... instead of the internal R1-R39 numbering used in
// v3.1.0-v3.1.13"). It collides with the real, unrelated PA-099 R37 (p.51,
// about weak/vulnerable Tier 0 certificates - see r37_weak_certs.go, where
// the ID collision is intentional: ANSSI_R37_WEAK_CERT_TEMPLATES actually IS
// R37). Official PA-099 R37 has nothing to do with AppLocker, advanced audit
// policy, or event log size. mappings.go already tags this detector ID
// against its real control (R11) - this Title/Description below is
// corrected to match, since an auditor reading a finding titled "ANSSI R37"
// would reasonably go looking for R37 in PA-099 and find something
// unrelated.
//
// This file, anssi-r38-advanced-audit-not-enabled.go and
// anssi-r39-security-log-too-small.go used to live together in
// r34_to_r39_hardening.go. v3.1.21 dedup: R34 (LSA Protection, WDigest) and
// R35 (Credential Guard), also originally in that file, were removed - they
// checked the exact same registry keys as the pre-existing custom detectors
// (LSA_PROTECTION_DISABLED, WDIGEST_ENABLED, CREDENTIAL_GUARD_DISABLED).
// Their PA-099 control mappings (R29, R62) were migrated onto the surviving
// custom detectors in mappings.go.

type R37AppLockerHeuristicDetector struct{ audit.BaseDetector }

func NewR37AppLockerHeuristicDetector() *R37AppLockerHeuristicDetector {
	return &R37AppLockerHeuristicDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R37_APPLOCKER_NOT_ENFORCED", audit.CategoryCompliance)}
}
func (d *R37AppLockerHeuristicDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// AppLocker config lives in AppLockerPolicy.xml under SYSVOL - not parsed
	// today. As a coarse heuristic, look for any GPO whose displayName mentions
	// AppLocker, WDAC, SRP or Code Integrity. Absence = likely no allow-listing.
	//
	// This is a name-based heuristic with real, structural blind spots: a
	// GPO enforcing AppLocker/WDAC under an unrelated name (e.g. "Corp
	// Security Baseline") silences neither a true positive nor a true
	// negative correctly either way, and AppLockerPolicy.xml itself (the
	// actual rule content under SYSVOL) is never parsed, so policy quality
	// is never checked even when a hinting GPO exists.
	hasHint := false
	for _, gpo := range data.GPOs {
		name := strings.ToLower(gpo.DisplayName)
		if strings.Contains(name, "applocker") || strings.Contains(name, "wdac") ||
			strings.Contains(name, "code integrity") || strings.Contains(name, "srp") {
			hasHint = true
			break
		}
	}
	count := 0
	if !hasHint {
		count = 1
	}
	return wrapFinding(d, "AppLocker / WDAC absent (heuristique GPO)",
		"ANSSI PA-099 R11 (p.28) recommends applying system/software hardening measures that contribute to Tier isolation, which includes application allow-listing (AppLocker, WDAC, or equivalent). HEURISTIC ONLY: no GPO display name mentions AppLocker / WDAC / Code Integrity / SRP. The actual policy quality (XML rules under SYSVOL) is not inspected by this detector, and a hinting or non-hinting GPO name proves nothing about whether allow-listing is actually enforced.",
		types.SeverityMedium, count, nil)
}

func init() {
	audit.MustRegister(NewR37AppLockerHeuristicDetector())
}
