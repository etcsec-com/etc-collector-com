package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LLMNRNotDisabledDetector checks if LLMNR is not disabled via GPO
type LLMNRNotDisabledDetector struct {
	audit.BaseDetector
}

func NewLLMNRNotDisabledDetector() *LLMNRNotDisabledDetector {
	return &LLMNRNotDisabledDetector{
		BaseDetector: audit.NewBaseDetector("GPO_LLMNR_NOT_DISABLED", audit.CategoryGPO),
	}
}

func (d *LLMNRNotDisabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "LLMNR Not Disabled",
		Description: "Link-Local Multicast Name Resolution (LLMNR) is not disabled via Group Policy. LLMNR responds to broadcast name queries and can be abused by attackers on the local network to capture NTLMv2 hashes via poisoning attacks (e.g., Responder).",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.LLMNRDisabled
	})

	// LLMNR is vulnerable if not configured (nil) or if set to 1 (enabled)
	if v == nil || *v != 0 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast to 0 via GPO.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLLMNRNotDisabledDetector())
}
