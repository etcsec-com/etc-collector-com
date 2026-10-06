package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

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
		Description: "Windows Credential Guard is not deployed via GPO. Credential Guard uses virtualization-based security to isolate NTLM hashes and Kerberos TGTs from direct memory access, preventing credential theft even if the OS is compromised. Enabling it requires BOTH the VBS master switch (DeviceGuard\\EnableVirtualizationBasedSecurity) and the Credential Guard switch itself (Lsa\\LsaCfgFlags) - VBS alone does not turn Credential Guard on.",
		Count:       0,
	}

	// Microsoft Learn, "Configure Credential Guard" (GPO tab): the "Turn On
	// Virtualization Based Security" policy under Computer Configuration >
	// Administrative Templates > System > Device Guard sets
	// DeviceGuard\EnableVirtualizationBasedSecurity (the VBS prerequisite),
	// while its nested "Credential Guard Configuration" dropdown ("Enabled
	// with UEFI lock" / "Enabled without lock") is what actually sets
	// Lsa\LsaCfgFlags to 1 or 2. Both must be set - VBS on its own only
	// prepares the platform, it does not turn Credential Guard on.
	// https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure
	vbs := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.CredentialGuardEnabled
	})
	lsaCfgFlags := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.LsaCfgFlags
	})

	vbsEnabled := vbs != nil && *vbs == 1
	credentialGuardConfigured := lsaCfgFlags != nil && (*lsaCfgFlags == 1 || *lsaCfgFlags == 2)

	if !vbsEnabled || !credentialGuardConfigured {
		finding.Count = 1
		details := map[string]interface{}{
			"recommendation":            "Enable Credential Guard via GPO: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security, with Credential Guard Configuration set to Enabled with UEFI lock (or Enabled without lock).",
			"vbsEnabled":                vbsEnabled,
			"credentialGuardConfigured": credentialGuardConfigured,
		}
		finding.Details = details
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCredentialGuardDetector())
}
