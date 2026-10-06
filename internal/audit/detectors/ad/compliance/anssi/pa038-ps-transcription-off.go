package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PA-038 group: see pa038-rdp-nla-not-required.go's package comment -
// "ANSSI PA-038" is not a real ANSSI document reference; this detector's
// citation has not been re-verified against a real source.

// --- PA038-5: PowerShell transcription off ---

type PA038PSTranscriptionDetector struct{ audit.BaseDetector }

func NewPA038PSTranscriptionDetector() *PA038PSTranscriptionDetector {
	return &PA038PSTranscriptionDetector{BaseDetector: audit.NewBaseDetector("PA038_PS_TRANSCRIPTION_OFF", audit.CategoryCompliance)}
}
func (d *PA038PSTranscriptionDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	enabled := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.PSTranscriptionEnabled != nil && *p.RegistrySettings.PSTranscriptionEnabled == 1 {
			enabled = true
			break
		}
	}
	count := 0
	if !enabled {
		count = 1
	}
	return wrapFinding(d, "PA-038 - PowerShell : Transcription non activée",
		"ANSSI PA-038 recommends PowerShell Transcription (EnableTranscripting=1) to write full session I/O to a central log path. Provides forensic audit trail for interactive PS sessions.",
		types.SeverityLow, count, nil)
}

func init() {
	audit.MustRegister(NewPA038PSTranscriptionDetector())
}
