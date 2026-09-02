package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PA-038: Recommandations de sécurité pour les systèmes Windows (ANSSI PA-038).
// 15 detectors covering GPO/registry hardening controls verifiable from SYSVOL.

// --- PA038-1: RDP NLA not required ---

type PA038RDPNLADetector struct{ audit.BaseDetector }

func NewPA038RDPNLADetector() *PA038RDPNLADetector {
	return &PA038RDPNLADetector{BaseDetector: audit.NewBaseDetector("PA038_RDP_NLA_NOT_REQUIRED", audit.CategoryCompliance)}
}
func (d *PA038RDPNLADetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	enforced := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.RDPNLA != nil && *p.RegistrySettings.RDPNLA == 1 {
			enforced = true
			break
		}
	}
	count := 0
	if !enforced {
		count = 1
	}
	return wrapFinding(d, "PA-038 — RDP : NLA (Network Level Authentication) non requis",
		"ANSSI PA-038 requires NLA for all RDP connections (HKLM\\...\\Terminal Services\\UserAuthentication=1). Without NLA, the Windows login screen is exposed before authentication, enabling DoS and pre-auth exploits.",
		types.SeverityHigh, count, nil)
}

// --- PA038-2: RDP security layer weak ---

type PA038RDPSecurityLayerDetector struct{ audit.BaseDetector }

func NewPA038RDPSecurityLayerDetector() *PA038RDPSecurityLayerDetector {
	return &PA038RDPSecurityLayerDetector{BaseDetector: audit.NewBaseDetector("PA038_RDP_SECURITY_LAYER_WEAK", audit.CategoryCompliance)}
}
func (d *PA038RDPSecurityLayerDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	enforced := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.RDPSecurityLayer != nil && *p.RegistrySettings.RDPSecurityLayer == 2 {
			enforced = true
			break
		}
	}
	count := 0
	if !enforced {
		count = 1
	}
	return wrapFinding(d, "PA-038 — RDP : couche de sécurité inférieure à TLS (SSL)",
		"ANSSI PA-038 requires RDP security layer = 2 (TLS/SSL). Values 0 (RDP native) and 1 (negotiate) allow downgrade attacks and weaker encryption.",
		types.SeverityHigh, count, nil)
}

// --- PA038-3: PowerShell ScriptBlock logging off ---

type PA038PSScriptBlockDetector struct{ audit.BaseDetector }

func NewPA038PSScriptBlockDetector() *PA038PSScriptBlockDetector {
	return &PA038PSScriptBlockDetector{BaseDetector: audit.NewBaseDetector("PA038_PS_SCRIPTBLOCK_LOGGING_OFF", audit.CategoryCompliance)}
}
func (d *PA038PSScriptBlockDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	enabled := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.PSScriptBlockLogging != nil && *p.RegistrySettings.PSScriptBlockLogging == 1 {
			enabled = true
			break
		}
	}
	count := 0
	if !enabled {
		count = 1
	}
	return wrapFinding(d, "PA-038 — PowerShell : Script Block Logging désactivé",
		"ANSSI PA-038 requires PowerShell Script Block Logging (EventID 4104) to detect obfuscated/malicious scripts executed in memory. Without it, PowerShell-based attacks (Empire, Cobalt Strike) leave no forensic trail.",
		types.SeverityMedium, count, nil)
}

// --- PA038-4: PowerShell module logging off ---

type PA038PSModuleLoggingDetector struct{ audit.BaseDetector }

func NewPA038PSModuleLoggingDetector() *PA038PSModuleLoggingDetector {
	return &PA038PSModuleLoggingDetector{BaseDetector: audit.NewBaseDetector("PA038_PS_MODULE_LOGGING_OFF", audit.CategoryCompliance)}
}
func (d *PA038PSModuleLoggingDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	enabled := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.PSModuleLogging != nil && *p.RegistrySettings.PSModuleLogging == 1 {
			enabled = true
			break
		}
	}
	count := 0
	if !enabled {
		count = 1
	}
	return wrapFinding(d, "PA-038 — PowerShell : Module Logging désactivé",
		"ANSSI PA-038 requires PowerShell Module Logging (EventID 4103) to record pipeline execution details per module. Complements Script Block Logging for full command visibility.",
		types.SeverityMedium, count, nil)
}

// --- PA038-5: PowerShell transcription off ---

type PA038PSTranscriptionDetector struct{ audit.BaseDetector }

func NewPA038PSTranscriptionDetector() *PA038PSTranscriptionDetector {
	return &PA038PSTranscriptionDetector{BaseDetector: audit.NewBaseDetector("PA038_PS_TRANSCRIPTION_OFF", audit.CategoryCompliance)}
}
func (d *PA038PSTranscriptionDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	enabled := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.PSTranscriptionEnabled != nil && *p.RegistrySettings.PSTranscriptionEnabled == 1 {
			enabled = true
			break
		}
	}
	count := 0
	if !enabled {
		count = 1
	}
	return wrapFinding(d, "PA-038 — PowerShell : Transcription non activée",
		"ANSSI PA-038 recommends PowerShell Transcription (EnableTranscripting=1) to write full session I/O to a central log path. Provides forensic audit trail for interactive PS sessions.",
		types.SeverityLow, count, nil)
}

// v3.1.21 dedup — PA038_LLMNR_ENABLED, PA038_HARDENED_UNC_PATHS_MISSING,
// PA038_BITLOCKER_NOT_REQUIRED, PA038_DEFENDER_ASR_NOT_ENABLED,
// PA038_FIREWALL_OUTBOUND_NOT_RESTRICTED removed — same registry keys as
// custom GPO_LLMNR_NOT_DISABLED / HARDENED_UNC_PATHS_WEAK /
// BITLOCKER_NOT_REQUIRED / DEFENDER_ASR_NOT_CONFIGURED /
// FIREWALL_OUTBOUND_NOT_BLOCKED. Mappings migrated in mappings.go.
//
// PA038_FIREWALL_OUTBOUND specifically had an inverted check (treated 0
// as block, real Microsoft semantics is 1=block) — false positives in
// production since v3.1.17. The custom FIREWALL_OUTBOUND_NOT_BLOCKED has
// the correct logic; deletion fixes the bug mechanically.

// --- PA038-12: WSUS not configured ---

type PA038WSUSDetector struct{ audit.BaseDetector }

func NewPA038WSUSDetector() *PA038WSUSDetector {
	return &PA038WSUSDetector{BaseDetector: audit.NewBaseDetector("PA038_WSUS_NOT_CONFIGURED", audit.CategoryCompliance)}
}
func (d *PA038WSUSDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	configured := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.WUServer != nil && *p.RegistrySettings.WUServer != "" {
			configured = true
			break
		}
	}
	count := 0
	if !configured {
		count = 1
	}
	return wrapFinding(d, "PA-038 — WSUS non configuré (mises à jour Windows non centralisées)",
		"ANSSI PA-038 requires centralized patch management. No GPO configures a WUServer (WSUS/MECM endpoint), meaning workstations may pull updates directly from Microsoft or not at all, making patch status unverifiable.",
		types.SeverityLow, count, nil)
}

// --- PA038-13: Point and Print elevation not enforced ---

type PA038PointAndPrintDetector struct{ audit.BaseDetector }

func NewPA038PointAndPrintDetector() *PA038PointAndPrintDetector {
	return &PA038PointAndPrintDetector{BaseDetector: audit.NewBaseDetector("PA038_POINT_AND_PRINT_ELEVATION_OFF", audit.CategoryCompliance)}
}
func (d *PA038PointAndPrintDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// PointAndPrintNoElevation=0 means elevation IS required (secure).
	// nil or 1 means no elevation required (PrintNightmare attack vector).
	enforced := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.PointAndPrintNoElevation != nil && *p.RegistrySettings.PointAndPrintNoElevation == 0 {
			enforced = true
			break
		}
	}
	count := 0
	if !enforced {
		count = 1
	}
	return wrapFinding(d, "PA-038 — Point and Print : élévation non requise (PrintNightmare)",
		"ANSSI PA-038 requires Point and Print restrictions to enforce elevation (NoWarningNoElevationOnInstall=0). CVE-2021-34527 (PrintNightmare) exploits this to install malicious printer drivers as SYSTEM.",
		types.SeverityHigh, count, nil)
}

// v3.1.21 dedup — PA038_ZEROLOGON_ENFORCEMENT_OFF removed (same key as
// custom ZEROLOGON_PATCH_ENFORCEMENT). Mapping migrated in mappings.go.

// --- PA038-15: NetCease / Net session hardening off ---

type PA038NetSessionHardeningDetector struct{ audit.BaseDetector }

func NewPA038NetSessionHardeningDetector() *PA038NetSessionHardeningDetector {
	return &PA038NetSessionHardeningDetector{BaseDetector: audit.NewBaseDetector("PA038_NET_SESSION_HARDENING_OFF", audit.CategoryCompliance)}
}
func (d *PA038NetSessionHardeningDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// NetSessionHardening restricts who can enumerate Net Sessions (SrvsvcSessionInfo).
	// Non-nil and > 0 = hardened. nil = default permissive (NetCease not applied).
	hardened := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.NetSessionHardening != nil && *p.RegistrySettings.NetSessionHardening > 0 {
			hardened = true
			break
		}
	}
	count := 0
	if !hardened {
		count = 1
	}
	return wrapFinding(d, "PA-038 — NetCease : énumération des sessions réseau non restreinte",
		"ANSSI PA-038 recommends applying NetCease (SrvsvcSessionInfo DACL restriction) to prevent unprivileged users from enumerating active SMB sessions via NetSessionEnum, which is used by BloodHound/SharpHound for user-to-host mapping.",
		types.SeverityMedium, count, nil)
}

func init() {
	audit.MustRegister(NewPA038RDPNLADetector())
	audit.MustRegister(NewPA038RDPSecurityLayerDetector())
	audit.MustRegister(NewPA038PSScriptBlockDetector())
	audit.MustRegister(NewPA038PSModuleLoggingDetector())
	audit.MustRegister(NewPA038PSTranscriptionDetector())
	audit.MustRegister(NewPA038WSUSDetector())
	audit.MustRegister(NewPA038PointAndPrintDetector())
	audit.MustRegister(NewPA038NetSessionHardeningDetector())
}
