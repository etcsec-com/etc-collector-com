package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NetSessionHardeningDetector checks if NetCease / net session hardening is configured
type NetSessionHardeningDetector struct {
	audit.BaseDetector
}

func NewNetSessionHardeningDetector() *NetSessionHardeningDetector {
	return &NetSessionHardeningDetector{
		BaseDetector: audit.NewBaseDetector("NET_SESSION_HARDENING_MISSING", audit.CategoryGPO),
	}
}

func (d *NetSessionHardeningDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Net Session Hardening Not Configured (NetCease)",
		Description: "Network session enumeration (NetSessionEnum) is not restricted. By default, any authenticated user can enumerate active sessions on servers, revealing which users are logged into which machines. This information is heavily used in attack path mapping (e.g., BloodHound session collection).",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.NetSessionHardening
	})

	if v == nil {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Deploy NetCease or configure SrvsvcSessionInfo permissions to restrict session enumeration to administrators only.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNetSessionHardeningDetector())
}
