package gpo

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WDigestDetector checks if WDigest authentication stores cleartext credentials in memory
type WDigestDetector struct {
	audit.BaseDetector
}

func NewWDigestDetector() *WDigestDetector {
	return &WDigestDetector{
		BaseDetector: audit.NewBaseDetector("WDIGEST_ENABLED", audit.CategoryGPO),
	}
}

func (d *WDigestDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "WDigest Authentication Stores Cleartext Credentials",
		Description: "WDigest UseLogonCredential is not explicitly disabled. On systems prior to Windows 8.1/2012 R2, or when enabled, WDigest stores cleartext passwords in LSASS memory, which can be extracted with tools like Mimikatz.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.WDigestUseLogonCredential
	})

	// If not configured (nil) or set to 1 (enabled), it's a risk
	if v == nil || *v != 0 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential to 0 via GPO.",
		}
	}

	return []types.Finding{finding}
}

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

	if v == nil || *v != 1 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Enable LSA Protection by setting HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL to 1 via GPO.",
		}
	}

	return []types.Finding{finding}
}

// CredentialGuardDetector checks if Credential Guard is enabled
type CredentialGuardDetector struct {
	audit.BaseDetector
}

func NewCredentialGuardDetector() *CredentialGuardDetector {
	return &CredentialGuardDetector{
		BaseDetector: audit.NewBaseDetector("CREDENTIAL_GUARD_DISABLED", audit.CategoryGPO),
	}
}

func (d *CredentialGuardDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Credential Guard Not Enabled",
		Description: "Windows Credential Guard is not deployed via GPO. Credential Guard uses virtualization-based security to isolate NTLM hashes and Kerberos TGTs from direct memory access, preventing credential theft even if the OS is compromised.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.CredentialGuardEnabled
	})

	if v == nil || *v != 1 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Enable Credential Guard via GPO: Computer Configuration > Administrative Templates > System > Device Guard > Turn on Virtualization Based Security.",
		}
	}

	return []types.Finding{finding}
}

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

// CachedLogonsDetector checks if cached logons count is excessive
type CachedLogonsDetector struct {
	audit.BaseDetector
}

func NewCachedLogonsDetector() *CachedLogonsDetector {
	return &CachedLogonsDetector{
		BaseDetector: audit.NewBaseDetector("CACHED_LOGONS_EXCESSIVE", audit.CategoryGPO),
	}
}

func (d *CachedLogonsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Excessive Cached Logons",
		Description: "Winlogon\\CachedLogonsCount > 4 (ANSSI PA-099 R34.1 threshold; ideally 0 on Tier 0). Cached MS-CACHE-V2 hashes can be cracked offline if a workstation is stolen, exposing the most recent interactive logons.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.CachedLogonsCount
	})

	// v3.1.21 — threshold aligned to ANSSI PA-099 R34.1 (>4) per the
	// official PDF (was >2 heuristic). The deleted ANSSI_R34_1_CACHED_LOGONS
	// detector used the same >4 trigger; this detector now satisfies its
	// mapping (PA-099 R29) without duplication.
	if v != nil && *v > 4 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"currentValue":   *v,
			"recommendation": "Set CachedLogonsCount to 4 or lower (ideally 0 on Tier 0) via GPO.",
		}
	}

	return []types.Finding{finding}
}

// RemoteSAMDetector checks if remote SAM access is restricted
type RemoteSAMDetector struct {
	audit.BaseDetector
}

func NewRemoteSAMDetector() *RemoteSAMDetector {
	return &RemoteSAMDetector{
		BaseDetector: audit.NewBaseDetector("SAM_REMOTE_ACCESS_OPEN", audit.CategoryGPO),
	}
}

func (d *RemoteSAMDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Remote SAM Access Not Restricted",
		Description: "The Security Account Manager (SAM) remote access is not restricted via GPO. By default, any authenticated user can enumerate local accounts and group memberships remotely, aiding reconnaissance.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingString(data.GPOPolicies, func(rs *audit.RegistrySettings) *string {
		return rs.RestrictRemoteSAM
	})

	if v == nil || !strings.Contains(*v, "D:") {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Configure RestrictRemoteSAM via GPO to limit SAM enumeration to administrators.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWDigestDetector())
	audit.MustRegister(NewLSAProtectionDetector())
	audit.MustRegister(NewCredentialGuardDetector())
	audit.MustRegister(NewNTLMv1Detector())
	audit.MustRegister(NewCachedLogonsDetector())
	audit.MustRegister(NewRemoteSAMDetector())
}
