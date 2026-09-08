package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NTLMv1Detector checks if NTLMv1 is still allowed
type NTLMv1Detector struct {
	audit.BaseDetector
}

func NewNTLMv1Detector() *NTLMv1Detector {
	return &NTLMv1Detector{
		BaseDetector: audit.NewBaseDetector("NTLMV1_ALLOWED", audit.CategoryGPO),
	}
}

func (d *NTLMv1Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "NTLMv1 Authentication Allowed",
		Description: "LAN Manager authentication level does not enforce NTLMv2-only. NTLMv1 responses can be cracked offline in seconds. Level 5 (Send NTLMv2 response only, refuse LM & NTLM) should be enforced.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.LmCompatibilityLevel
	})

	// Level 5 = NTLMv2 only, refuse LM & NTLM
	if v == nil || *v < 5 {
		finding.Count = 1
		details := map[string]interface{}{
			"recommendation": "Set LmCompatibilityLevel to 5 via GPO to enforce NTLMv2-only authentication.",
		}
		if v != nil {
			details["currentLevel"] = *v
		}
		finding.Details = details
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNTLMv1Detector())
}
