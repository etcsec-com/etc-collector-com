package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PA-038 group: see pa038-rdp-nla-not-required.go's package comment -
// "ANSSI PA-038" is not a real ANSSI document reference; this detector's
// citation has not been re-verified against a real source.

// --- PA038-4: PowerShell module logging off ---

type PA038PSModuleLoggingDetector struct{ audit.BaseDetector }

func NewPA038PSModuleLoggingDetector() *PA038PSModuleLoggingDetector {
	return &PA038PSModuleLoggingDetector{BaseDetector: audit.NewBaseDetector("PA038_PS_MODULE_LOGGING_OFF", audit.CategoryCompliance)}
}
func (d *PA038PSModuleLoggingDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	enabled := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.PSModuleLogging != nil && *p.RegistrySettings.PSModuleLogging == 1 {
			enabled = true
			break
		}
	}
	count := 0
	if !enabled {
		count = 1
	}
	return wrapFinding(d, "PA-038 - PowerShell : Module Logging désactivé",
		"ANSSI PA-038 requires PowerShell Module Logging (EventID 4103) to record pipeline execution details per module. Complements Script Block Logging for full command visibility.",
		types.SeverityMedium, count, nil)
}

func init() {
	audit.MustRegister(NewPA038PSModuleLoggingDetector())
}
