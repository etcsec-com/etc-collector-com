package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NetSessionHardeningDetector checks if NetCease / net session hardening is
// configured.
//
// Source check: a real NetCease/SrvsvcSessionInfo deployment writes a
// REG_BINARY security descriptor (see the field comment on
// RegistrySettings.NetSessionHardening - LanmanServer\DefaultSecurity\SrvsvcSessionInfo),
// but registrypol_parser.go's matching case only extracts the value via
// getDWORDValue, which reads .pol type-4 (REG_DWORD) entries. A real
// REG_BINARY NetCease value is a different .pol entry type and is never
// captured that way, so RegistrySettings.NetSessionHardening can currently
// never be populated by a genuinely hardened host either - this detector
// can flag the "not configured" case but cannot currently confirm the
// "configured" case is real. The REG_BINARY parsing path lives in
// internal/providers/smb/registrypol_parser.go, outside this detector
// file's scope for this pass; Description below discloses the gap
// instead of claiming full coverage.
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
		Description: "Network session enumeration (NetSessionEnum) is not restricted, or could not be confirmed as restricted. By default, any authenticated user can enumerate active sessions on servers, revealing which users are logged into which machines. This information is heavily used in attack path mapping (e.g., BloodHound session collection). Note: the real NetCease/SrvsvcSessionInfo value is a binary security descriptor that this collector's registry-policy parser does not currently extract, so a genuinely hardened host cannot yet be positively confirmed - this finding may under-report a properly configured host as unconfigured.",
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
