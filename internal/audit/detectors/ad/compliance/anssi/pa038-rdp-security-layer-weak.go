package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PA-038 group: see pa038-rdp-nla-not-required.go's package comment -
// "ANSSI PA-038" is not a real ANSSI document reference; this detector's
// citation has not been re-verified against a real source.

// --- PA038-2: RDP security layer weak ---

type PA038RDPSecurityLayerDetector struct{ audit.BaseDetector }

func NewPA038RDPSecurityLayerDetector() *PA038RDPSecurityLayerDetector {
	return &PA038RDPSecurityLayerDetector{BaseDetector: audit.NewBaseDetector("PA038_RDP_SECURITY_LAYER_WEAK", audit.CategoryCompliance)}
}
func (d *PA038RDPSecurityLayerDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	enforced := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.RDPSecurityLayer != nil && *p.RegistrySettings.RDPSecurityLayer == 2 {
			enforced = true
			break
		}
	}
	count := 0
	if !enforced {
		count = 1
	}
	return wrapFinding(d, "PA-038 - RDP : couche de sécurité inférieure à TLS (SSL)",
		"ANSSI PA-038 requires RDP security layer = 2 (TLS/SSL). Values 0 (RDP native) and 1 (negotiate) allow downgrade attacks and weaker encryption.",
		types.SeverityHigh, count, nil)
}

func init() {
	audit.MustRegister(NewPA038RDPSecurityLayerDetector())
}
