package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LSAProtectionDetector checks if LSA protection (RunAsPPL) is enabled
type LSAProtectionDetector struct {
	audit.BaseDetector
}

func NewLSAProtectionDetector() *LSAProtectionDetector {
	return &LSAProtectionDetector{
		BaseDetector: audit.NewBaseDetector("LSA_PROTECTION_DISABLED", audit.CategoryGPO),
	}
}

func (d *LSAProtectionDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "LSA Protection (RunAsPPL) Not Enabled",
		Description: "LSASS process is not running as a Protected Process Light (PPL). Without this protection, attackers can dump credentials directly from the LSASS process memory using tools like Mimikatz, procdump, or task manager.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.LSARunAsPPL
	})

	// Source: Microsoft Learn, "Configure added LSA protection" -
	// RunAsPPL=1 enables LSA protection with a UEFI-firmware lock,
	// RunAsPPL=2 enables it WITHOUT the UEFI lock (enforced on Windows 11
	// 22H2+ / Windows Server 2025, which defaults new installs to 2). Both
	// values mean LSASS is running as a Protected Process Light; treating
	// RunAsPPL=2 as "not enabled" (the old `*v != 1` check) would false-positive
	// on a correctly hardened Windows Server 2025 host.
	if v == nil || (*v != 1 && *v != 2) {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Enable LSA Protection by setting HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL to 1 (UEFI-locked) or 2 (unlocked, Windows 11 22H2+/Windows Server 2025) via GPO.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLSAProtectionDetector())
}
