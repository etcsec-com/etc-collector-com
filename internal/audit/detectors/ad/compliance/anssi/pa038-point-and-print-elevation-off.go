package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PA-038 group: see pa038-rdp-nla-not-required.go's package comment -
// "ANSSI PA-038" is not a real ANSSI document reference. This detector's
// citation/logic WAS re-verified in the v3.1.x salve referenced there.

// --- PA038-13: Point and Print elevation not enforced ---

type PA038PointAndPrintDetector struct{ audit.BaseDetector }

func NewPA038PointAndPrintDetector() *PA038PointAndPrintDetector {
	return &PA038PointAndPrintDetector{BaseDetector: audit.NewBaseDetector("PA038_POINT_AND_PRINT_ELEVATION_OFF", audit.CategoryCompliance)}
}
func (d *PA038PointAndPrintDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// PointAndPrintNoElevation=1 means elevation is NOT required
	// (vulnerable, the PrintNightmare install vector). =0 means elevation
	// IS required (secure, explicit).
	//
	// nil (no GPO sets this at all) was previously ALSO treated as
	// vulnerable - backwards per Microsoft's own KB5005010. Since the
	// August 10, 2021 cumulative updates, RestrictDriverInstallationTo
	// Administrators defaults to 1 in the shipped OS itself, so on any
	// currently-supported (patched) system, "no GPO override" leaves the
	// SECURE state in place, not the vulnerable one. Flagging nil as a
	// PrintNightmare finding asserted a vulnerability that isn't there on a
	// default, patched install. Only an explicit override to the insecure
	// value (1) is a genuine finding now. Also retagged: no ANSSI document
	// covers this (no "ANSSI PA-038" exists - see package comment above -
	// and PA-099's only mention of PrintNightmare is a passing footnote
	// about disabling the print spooler service entirely, a different
	// mitigation than this GPO); the citation is Microsoft's own security
	// advisory, not ANSSI.
	vulnerable := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.PointAndPrintNoElevation != nil && *p.RegistrySettings.PointAndPrintNoElevation == 1 {
			vulnerable = true
			break
		}
	}
	count := 0
	if vulnerable {
		count = 1
	}
	return wrapFinding(d, "Point and Print : élévation explicitement désactivée (PrintNightmare)",
		"A GPO explicitly sets Point and Print Restrictions to NOT require elevation (NoWarningNoElevationOnInstall=1), overriding the secure-by-default behavior Microsoft shipped in the August 10, 2021 cumulative updates (KB5005010) as the CVE-2021-34527 (PrintNightmare) mitigation. A system with no such GPO override relies on that shipped default (elevation required) and is not flagged.",
		types.SeverityHigh, count, nil)
}

// v3.1.21 dedup - PA038_ZEROLOGON_ENFORCEMENT_OFF removed (same key as
// custom ZEROLOGON_PATCH_ENFORCEMENT). Mapping migrated in mappings.go.

func init() {
	audit.MustRegister(NewPA038PointAndPrintDetector())
}
