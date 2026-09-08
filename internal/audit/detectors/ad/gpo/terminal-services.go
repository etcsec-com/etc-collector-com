package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TerminalServicesNotHardenedDetector checks if RDP/Terminal Services security settings are weak
type TerminalServicesNotHardenedDetector struct {
	audit.BaseDetector
}

func NewTerminalServicesNotHardenedDetector() *TerminalServicesNotHardenedDetector {
	return &TerminalServicesNotHardenedDetector{
		BaseDetector: audit.NewBaseDetector("TERMINAL_SERVICES_NOT_HARDENED", audit.CategoryGPO),
	}
}

func (d *TerminalServicesNotHardenedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Terminal Services / RDP Not Hardened",
		Description: "Remote Desktop Protocol (RDP) security settings are not properly hardened via GPO. Without NLA (Network Level Authentication) and TLS security layer, RDP sessions are vulnerable to man-in-the-middle attacks and credential theft.",
		Count:       0,
	}

	issues := []string{}

	// Check NLA (Network Level Authentication)
	nla := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.RDPNLA
	})
	if nla == nil || *nla != 1 {
		issues = append(issues, "NLA (Network Level Authentication) not required")
	}

	// Check security layer (2 = TLS)
	secLayer := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.RDPSecurityLayer
	})
	if secLayer == nil || *secLayer < 2 {
		issues = append(issues, "RDP security layer not set to TLS (value 2)")
	}

	finding.Count = len(issues)
	if len(issues) > 0 {
		finding.Details = map[string]interface{}{
			"issues":         issues,
			"recommendation": "Enable NLA and set security layer to TLS via GPO: Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Security.",
		}
		if data.IncludeDetails {
			entities := make([]types.AffectedEntity, len(issues))
			for i, issue := range issues {
				entities[i] = types.AffectedEntity{Type: "config", Name: issue}
			}
			finding.AffectedEntities = entities
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewTerminalServicesNotHardenedDetector())
}
