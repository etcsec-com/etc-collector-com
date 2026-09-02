package gpo

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WSUSHTTPDetector checks if WSUS is configured over HTTP instead of HTTPS
type WSUSHTTPDetector struct {
	audit.BaseDetector
}

func NewWSUSHTTPDetector() *WSUSHTTPDetector {
	return &WSUSHTTPDetector{
		BaseDetector: audit.NewBaseDetector("WSUS_HTTP_USED", audit.CategoryGPO),
	}
}

func (d *WSUSHTTPDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "WSUS Configured Over HTTP",
		Description: "Windows Server Update Services (WSUS) is configured to use HTTP instead of HTTPS. This allows attackers on the network to perform man-in-the-middle attacks and inject malicious updates, achieving code execution on all domain-joined machines.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingString(data.GPOPolicies, func(rs *audit.RegistrySettings) *string {
		return rs.WUServer
	})

	if v != nil && strings.HasPrefix(strings.ToLower(*v), "http://") {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"wsusURL":        *v,
			"recommendation": "Configure WSUS to use HTTPS and enable SSL on the WSUS server.",
		}
	}

	return []types.Finding{finding}
}

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
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "PrintNightmare Mitigation Not Applied",
		Description: "Point-and-Print restrictions are not configured to prevent PrintNightmare (CVE-2021-34527) exploitation. The NoWarningNoElevationOnInstall setting allows any user to install printer drivers from remote servers without elevation, enabling remote code execution as SYSTEM.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.PointAndPrintNoElevation
	})

	// If set to 1 (no warning/elevation required), it's vulnerable
	// If not configured, default behavior varies by Windows version
	if v != nil && *v == 1 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Set NoWarningNoElevationOnInstall to 0 and configure Point-and-Print restrictions via GPO. Consider disabling the Print Spooler service on servers that don't need printing.",
		}
	}

	return []types.Finding{finding}
}

// ZerologonDetector checks if Zerologon enforcement is enabled
type ZerologonDetector struct {
	audit.BaseDetector
}

func NewZerologonDetector() *ZerologonDetector {
	return &ZerologonDetector{
		BaseDetector: audit.NewBaseDetector("ZEROLOGON_PATCH_ENFORCEMENT", audit.CategoryGPO),
	}
}

func (d *ZerologonDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Zerologon (CVE-2020-1472) Enforcement Not Enabled",
		Description: "Secure channel enforcement for Zerologon (CVE-2020-1472) is not explicitly configured. Without FullSecureChannelProtection set to 1, Domain Controllers may still accept unauthenticated Netlogon connections, allowing complete domain takeover.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.ZerologonEnforcement
	})

	if v == nil || *v != 1 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\FullSecureChannelProtection to 1 and ensure all DCs are patched.",
		}
	}

	return []types.Finding{finding}
}

// BitLockerDetector checks if BitLocker is required via GPO
type BitLockerDetector struct {
	audit.BaseDetector
}

func NewBitLockerDetector() *BitLockerDetector {
	return &BitLockerDetector{
		BaseDetector: audit.NewBaseDetector("BITLOCKER_NOT_REQUIRED", audit.CategoryGPO),
	}
}

func (d *BitLockerDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "BitLocker Not Required via GPO",
		Description: "BitLocker drive encryption is not enforced via Group Policy. Without disk encryption, stolen or decommissioned hardware exposes Active Directory data, cached credentials, and other sensitive information.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.BitLockerRequired
	})

	if v == nil || *v != 1 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Enable BitLocker requirements via GPO and configure recovery key backup to Active Directory.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWSUSHTTPDetector())
	audit.MustRegister(NewPrintNightmareDetector())
	audit.MustRegister(NewZerologonDetector())
	audit.MustRegister(NewBitLockerDetector())
}
