package anssi

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ANSSI-BP-039 — Mise en œuvre des fonctionnalités de sécurité de Windows 10
// reposant sur la virtualisation (R5, R6/R7, R8, R9, R10*/R10**, R13, R14).
//
// Source: https://cyber.gouv.fr/sites/default/files/2017/11/np_securisation_windows10_securite_reposant_sur_la_virtualisation_v1.pdf
//
// All detectors below read GPO RegistrySettings populated by registrypol_parser
// from SYSVOL Registry.pol files. They emit a single Finding per detector, with
// Count=1 if no GPO enforces the recommendation domain-wide.

// gpoSetsAtLeast iterates GPOs and returns true when any policy has the named
// integer registry setting set to at least minVal. Helper used across BP-039
// detectors that all follow the same "is X enforced anywhere" pattern.
func gpoSetsAtLeast(data *audit.DetectorData, accessor func(*audit.RegistrySettings) *int, minVal int) bool {
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		v := accessor(p.RegistrySettings)
		if v != nil && *v >= minVal {
			return true
		}
	}
	return false
}

// gpoMaxValue iterates GPOs and returns the maximum value found for the named
// integer registry setting. Returns -1 if no GPO sets it. Used to evaluate
// "is the strongest setting in place" (e.g. LsaCfgFlags=2 for UEFI lock).
func gpoMaxValue(data *audit.DetectorData, accessor func(*audit.RegistrySettings) *int) int {
	max := -1
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		v := accessor(p.RegistrySettings)
		if v != nil && *v > max {
			max = *v
		}
	}
	return max
}

// --- BP-039 R5: VBS not enabled ---

type BP039VBSOffDetector struct{ audit.BaseDetector }

func NewBP039VBSOffDetector() *BP039VBSOffDetector {
	return &BP039VBSOffDetector{
		BaseDetector: audit.NewBaseDetector("BP039_VBS_OFF", audit.CategoryCompliance),
	}
}

func (d *BP039VBSOffDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// Reuse the existing CredentialGuardEnabled field which actually maps to
	// DeviceGuard\EnableVirtualizationBasedSecurity (the VBS master switch).
	if gpoSetsAtLeast(data, func(rs *audit.RegistrySettings) *int { return rs.CredentialGuardEnabled }, 1) {
		return nil
	}
	return wrapFinding(d, "ANSSI BP-039 R5 — VBS not enabled domain-wide",
		"ANSSI BP-039 R5 recommends enabling Virtualization-Based Security (VBS) on every compatible workstation. No GPO sets DeviceGuard\\EnableVirtualizationBasedSecurity to 1, so HVCI / Credential Guard / Code Integrity isolation cannot benefit from hypervisor-enforced protections.",
		types.SeverityMedium, 1, nil)
}

// --- BP-039 R8: HVCI not enabled ---

type BP039HVCIOffDetector struct{ audit.BaseDetector }

func NewBP039HVCIOffDetector() *BP039HVCIOffDetector {
	return &BP039HVCIOffDetector{
		BaseDetector: audit.NewBaseDetector("BP039_HVCI_OFF", audit.CategoryCompliance),
	}
}

func (d *BP039HVCIOffDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	if gpoSetsAtLeast(data, func(rs *audit.RegistrySettings) *int { return rs.HVCIEnabled }, 1) {
		return nil
	}
	return wrapFinding(d, "ANSSI BP-039 R8 — HVCI not enabled",
		"ANSSI BP-039 R8 recommends enabling Hypervisor-Enforced Code Integrity (HVCI) on every compatible workstation. No GPO sets DeviceGuard\\HypervisorEnforcedCodeIntegrity, so kernel-mode integrity verification doesn't run inside the secure VBS partition.",
		types.SeverityMedium, 1, nil)
}

// --- BP-039 R9: HVCI without UEFI lock ---

type BP039HVCINoUEFILockDetector struct{ audit.BaseDetector }

func NewBP039HVCINoUEFILockDetector() *BP039HVCINoUEFILockDetector {
	return &BP039HVCINoUEFILockDetector{
		BaseDetector: audit.NewBaseDetector("BP039_HVCI_NO_UEFI_LOCK", audit.CategoryCompliance),
	}
}

func (d *BP039HVCINoUEFILockDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	maxHVCI := gpoMaxValue(data, func(rs *audit.RegistrySettings) *int { return rs.HVCIEnabled })
	// HVCIEnabled = 1 means enabled without UEFI lock; 2 means with lock.
	// If HVCI is on (>=1) but never reaches 2, ANSSI R9 isn't satisfied.
	if maxHVCI < 1 {
		return nil // covered by R8 instead
	}
	if maxHVCI >= 2 {
		return nil // R9 satisfied
	}
	return wrapFinding(d, "ANSSI BP-039 R9 — HVCI enabled without UEFI lock",
		"ANSSI BP-039 R9 requires HVCI to be deployed with UEFI lock. Current GPOs enable HVCI (=1) but no GPO sets it to 2 (with UEFI lock), so a local administrator can disable HVCI from the OS without UEFI access.",
		types.SeverityLow, 1, nil)
}

// --- BP-039 R10: Credential Guard not deployed (presence) + R10*/R10** scope ---
// ANSSI_R35_CREDENTIAL_GUARD_OFF already covers the basic "Credential Guard
// off" case mapped to BP-039 R10. Here we add the scope variants R10* (sensitive
// workstations only) vs R10** (all workstations) — when CredGuard is enabled
// but only LsaCfgFlags=1 is set, scope is "sensitive only".

type BP039CredGuardLimitedScopeDetector struct{ audit.BaseDetector }

func NewBP039CredGuardLimitedScopeDetector() *BP039CredGuardLimitedScopeDetector {
	return &BP039CredGuardLimitedScopeDetector{
		BaseDetector: audit.NewBaseDetector("BP039_CRED_GUARD_LIMITED_SCOPE", audit.CategoryCompliance),
	}
}

func (d *BP039CredGuardLimitedScopeDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// v3.1.18 — exact scope check via GPOLinks (was: count of GPOs).
	// R10**  = Credential Guard ON every workstation (= GPO linked at domain root).
	// R10*   = Credential Guard ON sensitive-only (= linked to Tier 0 OU(s)).
	// We fire if NO GPO with LsaCfgFlags>=1 is linked at the domain root.
	maxCG := gpoMaxValue(data, func(rs *audit.RegistrySettings) *int { return rs.LsaCfgFlags })
	if maxCG < 1 {
		return nil // not enabled at all → covered by R35 instead
	}
	domainDN := ""
	if data.DomainInfo != nil {
		domainDN = data.DomainInfo.DomainDN
	}
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.LsaCfgFlags == nil || *p.RegistrySettings.LsaCfgFlags < 1 {
			continue
		}
		scope := helpers.ComputeGPOScope(data, p.GUID, domainDN)
		if scope.LinkedToDomain {
			return nil // R10** satisfied
		}
	}
	return wrapFinding(d, "ANSSI BP-039 R10** — Credential Guard scope appears limited",
		"ANSSI BP-039 R10** recommends Credential Guard on ALL workstations (R10* is the lower-bar variant for sensitive ones only). No GPO with LsaCfgFlags>=1 is linked at the domain root, so deployment is restricted to a subset of OUs. Link the Credential Guard GPO at the domain root for full coverage (defense in depth).",
		types.SeverityLow, 1, nil)
}

// --- BP-039 R14: Credential Guard without UEFI lock ---

type BP039CredGuardNoUEFILockDetector struct{ audit.BaseDetector }

func NewBP039CredGuardNoUEFILockDetector() *BP039CredGuardNoUEFILockDetector {
	return &BP039CredGuardNoUEFILockDetector{
		BaseDetector: audit.NewBaseDetector("BP039_CRED_GUARD_NO_UEFI_LOCK", audit.CategoryCompliance),
	}
}

func (d *BP039CredGuardNoUEFILockDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	maxCG := gpoMaxValue(data, func(rs *audit.RegistrySettings) *int { return rs.LsaCfgFlags })
	if maxCG < 1 {
		return nil // not enabled, covered by R35
	}
	if maxCG >= 2 {
		return nil // UEFI lock present
	}
	return wrapFinding(d, "ANSSI BP-039 R14 — Credential Guard enabled without UEFI lock",
		"ANSSI BP-039 R14 requires Credential Guard to be activated with UEFI lock (LsaCfgFlags=2). Current GPOs set LsaCfgFlags to 1 (enabled, no lock), allowing a local admin to disable the protection from the OS at next reboot.",
		types.SeverityMedium, 1, nil)
}

// --- BP-039 R6/R7: Configurable Code Integrity (CCI / WDAC) not deployed ---

type BP039CCINotDeployedDetector struct{ audit.BaseDetector }

func NewBP039CCINotDeployedDetector() *BP039CCINotDeployedDetector {
	return &BP039CCINotDeployedDetector{
		BaseDetector: audit.NewBaseDetector("BP039_CCI_NOT_DEPLOYED", audit.CategoryCompliance),
	}
}

func (d *BP039CCINotDeployedDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// Two signals indicate CCI/WDAC deployment:
	//  1. ConfigCIPolicyFilePath is set in any GPO (path to the .p7b/.cip file)
	//  2. DeviceGuardCodeIntegrityPolicyEnforcement >= 1 (RequirePlatformSecurityFeatures)
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.DeviceGuardConfigCIPolicyFilePath != nil && *p.RegistrySettings.DeviceGuardConfigCIPolicyFilePath != "" {
			return nil
		}
		if p.RegistrySettings.DeviceGuardCodeIntegrityPolicyEnforcement != nil && *p.RegistrySettings.DeviceGuardCodeIntegrityPolicyEnforcement >= 1 {
			return nil
		}
	}
	return wrapFinding(d, "ANSSI BP-039 R6/R7 — Configurable Code Integrity (CCI/WDAC) not deployed",
		"ANSSI BP-039 R6 (sensitive workstations) and R7 (other workstations) recommend deploying Configurable Code Integrity / WDAC. No GPO references CodeIntegrity\\ConfigCIPolicyFilePath nor sets DeviceGuard\\RequirePlatformSecurityFeatures, so kernel-mode + user-mode binaries aren't constrained to a signed allowlist.",
		types.SeverityLow, 1, nil)
}

// --- BP-039 R13: AD privileged accounts cached on workstations ---

type BP039PrivAccountsCachedDetector struct{ audit.BaseDetector }

func NewBP039PrivAccountsCachedDetector() *BP039PrivAccountsCachedDetector {
	return &BP039PrivAccountsCachedDetector{
		BaseDetector: audit.NewBaseDetector("BP039_PRIV_ACCOUNTS_CACHED", audit.CategoryCompliance),
	}
}

func (d *BP039PrivAccountsCachedDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// CachedLogonsCount > 0 means cached credentials are kept locally. ANSSI
	// BP-039 R13 forbids caching AD privileged accounts; the strongest signal
	// is when no GPO ever sets the cache to 0. Default Windows = 10.
	cacheZeroed := false
	worstSeen := -1
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.CachedLogonsCount != nil {
			if *p.RegistrySettings.CachedLogonsCount == 0 {
				cacheZeroed = true
			}
			if *p.RegistrySettings.CachedLogonsCount > worstSeen {
				worstSeen = *p.RegistrySettings.CachedLogonsCount
			}
		}
	}
	if cacheZeroed {
		return nil // at least one GPO disables caching
	}
	msg := "ANSSI BP-039 R13 forbids caching AD privileged accounts on workstations. "
	if worstSeen < 0 {
		msg += "No GPO sets Winlogon\\CachedLogonsCount, so the Windows default (10) applies — the last 10 interactive logons (including Tier 0 admins) are cached on disk and recoverable by an attacker with local SYSTEM."
	} else {
		msg += fmt.Sprintf("Highest CachedLogonsCount observed across GPOs is %d (recommended: 0 on workstations that may host privileged interactive logons).", worstSeen)
	}
	return wrapFinding(d, "ANSSI BP-039 R13 — AD privileged accounts cached on workstations",
		msg, types.SeverityMedium, 1, nil)
}

func init() {
	audit.MustRegister(NewBP039VBSOffDetector())
	audit.MustRegister(NewBP039HVCIOffDetector())
	audit.MustRegister(NewBP039HVCINoUEFILockDetector())
	audit.MustRegister(NewBP039CredGuardLimitedScopeDetector())
	audit.MustRegister(NewBP039CredGuardNoUEFILockDetector())
	audit.MustRegister(NewBP039CCINotDeployedDetector())
	audit.MustRegister(NewBP039PrivAccountsCachedDetector())
}
