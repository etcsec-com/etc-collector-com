package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DefenderASRDetector checks if Microsoft Defender Attack Surface Reduction rules are configured
type DefenderASRDetector struct {
	audit.BaseDetector
}

func NewDefenderASRDetector() *DefenderASRDetector {
	return &DefenderASRDetector{
		BaseDetector: audit.NewBaseDetector("DEFENDER_ASR_NOT_CONFIGURED", audit.CategoryGPO),
	}
}

func (d *DefenderASRDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Defender Attack Surface Reduction Not Configured",
		Description: "Microsoft Defender Attack Surface Reduction (ASR) rules are not deployed via GPO. ASR rules block common attack techniques such as Office macro execution, script obfuscation, credential stealing from LSASS, and other malware delivery methods.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.DefenderASREnabled
	})

	if v == nil || *v != 1 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Enable ASR rules via GPO: Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Windows Defender Exploit Guard > Attack Surface Reduction.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDefenderASRDetector())
}
