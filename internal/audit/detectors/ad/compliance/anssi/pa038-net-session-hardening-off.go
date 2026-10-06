package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PA-038 group: see pa038-rdp-nla-not-required.go's package comment -
// "ANSSI PA-038" is not a real ANSSI document reference. This detector's
// citation/logic WAS re-verified in the v3.1.x salve referenced there.

// --- PA038-15: NetCease / Net session hardening off ---

type PA038NetSessionHardeningDetector struct{ audit.BaseDetector }

func NewPA038NetSessionHardeningDetector() *PA038NetSessionHardeningDetector {
	return &PA038NetSessionHardeningDetector{BaseDetector: audit.NewBaseDetector("PA038_NET_SESSION_HARDENING_OFF", audit.CategoryCompliance)}
}
func (d *PA038NetSessionHardeningDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// NetSessionHardening restricts who can enumerate Net Sessions (SrvsvcSessionInfo).
	// Non-nil and > 0 = a DWORD-style value is set at that registry path.
	//
	// Two fixes.
	//  1. No ANSSI document (PA-099, PB-090, or the general ANSSI corpus)
	//     mentions NetCease, SrvsvcSessionInfo, or NetSessionEnum hardening
	//     at all - "ANSSI PA-038" was fabricated (see package comment
	//     above). Retagged as a product-defined heuristic with no framework
	//     attribution.
	//  2. Structurally narrow, causing a false positive on every domain
	//     hardened via the real technique: NetCease sets a
	//     security-descriptor (REG_BINARY SDDL) ACL at
	//     LanmanServer\DefaultSecurity\SrvsvcSessionInfo, or is applied
	//     outside Group Policy entirely (a logon script / manual registry
	//     edit) - registrypol_parser.go only recognizes a DWORD value at
	//     that same path (getDWORDValue, registrypol_parser.go:320), which
	//     is not what the real mitigation writes there. A domain hardened
	//     the standard way parses as unset (nil) every time, so this can
	//     only detect a non-standard DWORD-style convention, never the
	//     actual mitigation - "not hardened" is not a safe conclusion from
	//     this signal. Lowered to Info and reworded accordingly.
	hardened := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.NetSessionHardening != nil && *p.RegistrySettings.NetSessionHardening > 0 {
			hardened = true
			break
		}
	}
	count := 0
	if !hardened {
		count = 1
	}
	return wrapFinding(d, "NetCease : aucun réglage DWORD de restriction des sessions réseau détecté",
		"No GPO sets a DWORD-style value at LanmanServer\\DefaultSecurity\\SrvsvcSessionInfo. This is a product-defined heuristic, not an ANSSI requirement (no ANSSI document covering NetCease/SrvsvcSessionInfo hardening was found). It is also narrow: the real NetCease mitigation applies a security-descriptor (REG_BINARY) ACL at this same registry path, or is applied outside Group Policy entirely - neither is visible to this DWORD-only check, so a domain hardened via the standard method will still show this finding. Treat as 'no simple registry toggle observed', not a confirmed absence of NetCease.",
		types.SeverityInfo, count, nil)
}

func init() {
	audit.MustRegister(NewPA038NetSessionHardeningDetector())
}
