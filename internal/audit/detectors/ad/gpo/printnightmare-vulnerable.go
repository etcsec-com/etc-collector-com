package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PrintNightmareDetector checks if Point-and-Print is not restricted (PrintNightmare mitigation)
type PrintNightmareDetector struct {
	audit.BaseDetector
}

func NewPrintNightmareDetector() *PrintNightmareDetector {
	return &PrintNightmareDetector{
		BaseDetector: audit.NewBaseDetector("PRINTNIGHTMARE_VULNERABLE", audit.CategoryGPO),
	}
}

func (d *PrintNightmareDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityCritical,
		Category: string(d.Category()),
		Title:    "Point and Print: No-Warning Driver Install for New Connections (PrintNightmare Exposure)",
		// Honest scope note (KB5005010, "Restricting installation of new
		// printer drivers"): the Point and Print Restrictions policy
		// (Computer Configuration > Administrative Templates > Printers)
		// actually writes TWO independent registry values under
		// HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint -
		// NoWarningNoElevationOnInstall ("When installing drivers for a new
		// connection") and UpdatePromptSettings ("When updating drivers for
		// an existing connection"). Only the first is collected today
		// (RegistrySettings has no field for the second - adding one is out
		// of scope for this fix). So this detector can only ever confirm or
		// clear the "new connection" half of Microsoft's guidance; a domain
		// that hardens NoWarningNoElevationOnInstall but leaves
		// UpdatePromptSettings unsafe would read clean here despite still
		// being exploitable via an existing printer connection's driver
		// update path. Microsoft's more complete, order-independent fix
		// (RestrictDriverInstallationToAdministrators, defaulting to enabled
		// since the August 10, 2021 update) is also not collected.
		Description: "Point-and-Print restrictions do not require a warning/elevation prompt when installing drivers for a NEW printer connection (NoWarningNoElevationOnInstall=1), the classic PrintNightmare (CVE-2021-34527) install-time vector. This check covers only that one of Microsoft's two Point and Print registry values - it does not evaluate UpdatePromptSettings (drivers for an EXISTING connection) or RestrictDriverInstallationToAdministrators, so a clean result here does not by itself confirm full KB5005010 mitigation.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.PointAndPrintNoElevation
	})

	// Source: Microsoft KB5005010, "Restricting installation of new printer
	// drivers after applying the July 6, 2021 updates" - under
	// HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint,
	// NoWarningNoElevationOnInstall = 0 or absent (safe: prompt shown) vs.
	// a non-zero value (unsafe: silently installs without elevation).
	if v != nil && *v == 1 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Set NoWarningNoElevationOnInstall to 0 (or leave undefined) and additionally set UpdatePromptSettings to 0 and RestrictDriverInstallationToAdministrators to 1 - NoWarningNoElevationOnInstall alone only covers new printer connections, not driver updates on existing ones. Consider disabling the Print Spooler service on servers that don't need printing.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPrintNightmareDetector())
}
