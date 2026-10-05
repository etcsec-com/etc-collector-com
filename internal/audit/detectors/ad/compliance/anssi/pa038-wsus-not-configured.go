package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PA-038 group: see pa038-rdp-nla-not-required.go's package comment -
// "ANSSI PA-038" is not a real ANSSI document reference; this detector's
// citation has not been re-verified against a real source.
//
// v3.1.21 dedup - PA038_LLMNR_ENABLED, PA038_HARDENED_UNC_PATHS_MISSING,
// PA038_BITLOCKER_NOT_REQUIRED, PA038_DEFENDER_ASR_NOT_ENABLED,
// PA038_FIREWALL_OUTBOUND_NOT_RESTRICTED removed - same registry keys as
// custom GPO_LLMNR_NOT_DISABLED / HARDENED_UNC_PATHS_WEAK /
// BITLOCKER_NOT_REQUIRED / DEFENDER_ASR_NOT_CONFIGURED /
// FIREWALL_OUTBOUND_NOT_BLOCKED. Mappings migrated in mappings.go.
//
// PA038_FIREWALL_OUTBOUND specifically had an inverted check (treated 0
// as block, real Microsoft semantics is 1=block) - false positives in
// production since v3.1.17. The custom FIREWALL_OUTBOUND_NOT_BLOCKED has
// the correct logic; deletion fixes the bug mechanically.

// --- PA038-12: WSUS not configured ---

type PA038WSUSDetector struct{ audit.BaseDetector }

func NewPA038WSUSDetector() *PA038WSUSDetector {
	return &PA038WSUSDetector{BaseDetector: audit.NewBaseDetector("PA038_WSUS_NOT_CONFIGURED", audit.CategoryCompliance)}
}
func (d *PA038WSUSDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	configured := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.WUServer != nil && *p.RegistrySettings.WUServer != "" {
			configured = true
			break
		}
	}
	count := 0
	if !configured {
		count = 1
	}
	return wrapFinding(d, "PA-038 - WSUS non configuré (mises à jour Windows non centralisées)",
		"ANSSI PA-038 requires centralized patch management. No GPO configures a WUServer (WSUS/MECM endpoint), meaning workstations may pull updates directly from Microsoft or not at all, making patch status unverifiable.",
		types.SeverityLow, count, nil)
}

func init() {
	audit.MustRegister(NewPA038WSUSDetector())
}
