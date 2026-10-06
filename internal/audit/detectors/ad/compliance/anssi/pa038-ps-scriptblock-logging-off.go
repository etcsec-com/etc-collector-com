package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PA-038 group: see pa038-rdp-nla-not-required.go's package comment -
// "ANSSI PA-038" is not a real ANSSI document reference; this detector's
// citation has not been re-verified against a real source.

// --- PA038-3: PowerShell ScriptBlock logging off ---

type PA038PSScriptBlockDetector struct{ audit.BaseDetector }

func NewPA038PSScriptBlockDetector() *PA038PSScriptBlockDetector {
	return &PA038PSScriptBlockDetector{BaseDetector: audit.NewBaseDetector("PA038_PS_SCRIPTBLOCK_LOGGING_OFF", audit.CategoryCompliance)}
}
func (d *PA038PSScriptBlockDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	enabled := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.PSScriptBlockLogging != nil && *p.RegistrySettings.PSScriptBlockLogging == 1 {
			enabled = true
			break
		}
	}
	count := 0
	if !enabled {
		count = 1
	}
	return wrapFinding(d, "PA-038 - PowerShell : Script Block Logging désactivé",
		"ANSSI PA-038 requires PowerShell Script Block Logging (EventID 4104) to detect obfuscated/malicious scripts executed in memory. Without it, PowerShell-based attacks (Empire, Cobalt Strike) leave no forensic trail.",
		types.SeverityMedium, count, nil)
}

func init() {
	audit.MustRegister(NewPA038PSScriptBlockDetector())
}
