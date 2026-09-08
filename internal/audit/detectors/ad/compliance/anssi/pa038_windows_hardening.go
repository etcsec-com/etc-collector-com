package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PA-038: Recommandations de sécurité pour les systèmes Windows (ANSSI PA-038).
// 15 detectors covering GPO/registry hardening controls verifiable from SYSVOL.
//
// "ANSSI PA-038" is not a real ANSSI document reference - verified
// against ANSSI's own published catalog, no such reference code exists. This
// salve only re-verified and fixed the citation/logic for
// PA038_NET_SESSION_HARDENING_OFF and PA038_POINT_AND_PRINT_ELEVATION_OFF
// below (see their own comments for what was actually checked and what the
// real sources are, where one exists). The "PA-038" attribution on the other
// detectors in this file has NOT been re-verified in this salve and may be
// similarly wrong - noted as a needed follow-up, out of scope here.

// --- PA038-1: RDP NLA not enforced via GPO ---
//
// Source: ANSSI PA-099 R18 (p.35, "Appliquer les security baselines aux
// systèmes du Tier 0") requires applying Microsoft's published security
// baselines; Microsoft's Security Compliance Toolkit baseline for Windows
// Server sets "Require user authentication for remote connections by using
// Network Level Authentication" (Computer Configuration > Administrative
// Templates > Windows Components > Remote Desktop Services > Remote Desktop
// Session Host > Security, registry HKLM\SOFTWARE\Policies\Microsoft\
// Windows NT\Terminal Services\UserAuthentication) to Enabled - same control
// as CIS Microsoft Windows Server Benchmark (e.g. 18.10.56.3.9.4 in the 2022
// edition). This is the real citation, already used for this detector in
// compliance/mappings.go; "ANSSI PA-038" (the string previously used here)
// is not a real ANSSI document (see package comment above) and has been
// dropped.
//
// Name/measure mismatch: this only observes Group Policy. Per Microsoft's
// own reference ("Configure Network Level Authentication for Remote Desktop
// Services Connections", learn.microsoft.com/previous-versions/windows/
// it-pro/windows-server-2008-R2-and-2008/cc732713), NLA can also be turned
// on locally - RD Session Host Configuration, or the Remote tab in System
// Properties, which Windows Server has shipped checked by default since
// Server 2012 R2 - and "the Group Policy setting will take precedence over
// the setting configured in Remote Desktop Session Host Configuration or on
// the Remote tab", meaning the local value still applies whenever no GPO is
// set. A host with NLA enabled locally (the modern default) is therefore
// NOT actually vulnerable, even though this detector - GPO-only - has no
// way to see that. Retitled from "non requis" (an absolute claim about
// exposure this data can't support) to "non imposé par GPO" (exactly what
// is measured: the control isn't centrally enforced and could be silently
// unchecked by a local admin with nothing to stop them). Severity lowered
// from High to Medium to match: this is a policy-enforcement gap, not a
// confirmed-vulnerable host - the same reasoning already applied at Medium
// to the equivalent GPO-only NLA+security-layer check in
// gpo.TerminalServicesNotHardenedDetector elsewhere in this codebase.

type PA038RDPNLADetector struct{ audit.BaseDetector }

func NewPA038RDPNLADetector() *PA038RDPNLADetector {
	return &PA038RDPNLADetector{BaseDetector: audit.NewBaseDetector("PA038_RDP_NLA_NOT_REQUIRED", audit.CategoryCompliance)}
}
func (d *PA038RDPNLADetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// An empty data.GPOPolicies means SYSVOL was never reached
	// (ACL denied, DC down, 445 filtered) - not "no GPO sets
	// UserAuthentication". Same guard as SMB_SIGNING_DISABLED /
	// LDAP_SIGNING_DISABLED does the same: distinguish "measured, absent"
	// from "not measurable" so a client whose SYSVOL is unreachable isn't
	// scored as vulnerable by default.
	if len(data.GPOPolicies) == 0 {
		return wrapFinding(d, "RDP : NLA (Network Level Authentication) non imposée par GPO",
			"ANSSI PA-099 R18 (p.35) requires applying Microsoft's published security baselines to Tier 0 systems; Microsoft's baseline for Windows Server sets 'Require user authentication for remote connections by using Network Level Authentication' to Enabled (HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\UserAuthentication=1; same control as CIS Microsoft Windows Server Benchmark, e.g. 18.10.56.3.9.4 in the 2022 edition). This only measures Group Policy: NLA can also be enabled locally (RD Session Host Configuration, or the Remote tab in System Properties - checked by default on Windows Server since 2012 R2), which still applies whenever no GPO is set. 'No GPO enforces NLA' means the control is not centrally enforced, not that NLA is confirmed off on this host.",
			types.SeverityMedium, 0, nil)
	}
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
	return wrapFinding(d, "RDP : NLA (Network Level Authentication) non imposée par GPO",
		"ANSSI PA-099 R18 (p.35) requires applying Microsoft's published security baselines to Tier 0 systems; Microsoft's baseline for Windows Server sets 'Require user authentication for remote connections by using Network Level Authentication' to Enabled (HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\UserAuthentication=1; same control as CIS Microsoft Windows Server Benchmark, e.g. 18.10.56.3.9.4 in the 2022 edition). This only measures Group Policy: NLA can also be enabled locally (RD Session Host Configuration, or the Remote tab in System Properties - checked by default on Windows Server since 2012 R2), which still applies whenever no GPO is set. 'No GPO enforces NLA' means the control is not centrally enforced, not that NLA is confirmed off on this host.",
		types.SeverityMedium, count, nil)
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
	return wrapFinding(d, "PA-038 - RDP : couche de sécurité inférieure à TLS (SSL)",
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
	return wrapFinding(d, "PA-038 - PowerShell : Script Block Logging désactivé",
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
	return wrapFinding(d, "PA-038 - PowerShell : Module Logging désactivé",
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
	return wrapFinding(d, "PA-038 - PowerShell : Transcription non activée",
		"ANSSI PA-038 recommends PowerShell Transcription (EnableTranscripting=1) to write full session I/O to a central log path. Provides forensic audit trail for interactive PS sessions.",
		types.SeverityLow, count, nil)
}

// v3.1.21 dedup - PA038_LLMNR_ENABLED, PA038_HARDENED_UNC_PATHS_MISSING,
// PA038_BITLOCKER_NOT_REQUIRED, PA038_DEFENDER_ASR_NOT_ENABLED,
// PA038_FIREWALL_OUTBOUND_NOT_RESTRICTED removed - same registry keys as
// custom GPO_LLMNR_NOT_DISABLED / HARDENED_UNC_PATHS_WEAK /
// BITLOCKER_NOT_REQUIRED / DEFENDER_ASR_NOT_CONFIGURED /
// FIREWALL_OUTBOUND_NOT_BLOCKED. Mappings migrated in mappings.go.
//
// PA038_FIREWALL_OUTBOUND specifically had an inverted check (treated 0
// as block, real Microsoft semantics is 1=block) - false positives in
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
	return wrapFinding(d, "PA-038 - WSUS non configuré (mises à jour Windows non centralisées)",
		"ANSSI PA-038 requires centralized patch management. No GPO configures a WUServer (WSUS/MECM endpoint), meaning workstations may pull updates directly from Microsoft or not at all, making patch status unverifiable.",
		types.SeverityLow, count, nil)
}

// --- PA038-13: Point and Print elevation not enforced ---

type PA038PointAndPrintDetector struct{ audit.BaseDetector }

func NewPA038PointAndPrintDetector() *PA038PointAndPrintDetector {
	return &PA038PointAndPrintDetector{BaseDetector: audit.NewBaseDetector("PA038_POINT_AND_PRINT_ELEVATION_OFF", audit.CategoryCompliance)}
}
func (d *PA038PointAndPrintDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// PointAndPrintNoElevation=1 means elevation is NOT required
	// (vulnerable, the PrintNightmare install vector). =0 means elevation
	// IS required (secure, explicit).
	//
	// nil (no GPO sets this at all) was previously ALSO treated as
	// vulnerable - backwards per Microsoft's own KB5005010. Since the
	// August 10, 2021 cumulative updates, RestrictDriverInstallationTo
	// Administrators defaults to 1 in the shipped OS itself, so on any
	// currently-supported (patched) system, "no GPO override" leaves the
	// SECURE state in place, not the vulnerable one. Flagging nil as a
	// PrintNightmare finding asserted a vulnerability that isn't there on a
	// default, patched install. Only an explicit override to the insecure
	// value (1) is a genuine finding now. Also retagged: no ANSSI document
	// covers this (no "ANSSI PA-038" exists - see package comment above -
	// and PA-099's only mention of PrintNightmare is a passing footnote
	// about disabling the print spooler service entirely, a different
	// mitigation than this GPO); the citation is Microsoft's own security
	// advisory, not ANSSI.
	vulnerable := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.PointAndPrintNoElevation != nil && *p.RegistrySettings.PointAndPrintNoElevation == 1 {
			vulnerable = true
			break
		}
	}
	count := 0
	if vulnerable {
		count = 1
	}
	return wrapFinding(d, "Point and Print : élévation explicitement désactivée (PrintNightmare)",
		"A GPO explicitly sets Point and Print Restrictions to NOT require elevation (NoWarningNoElevationOnInstall=1), overriding the secure-by-default behavior Microsoft shipped in the August 10, 2021 cumulative updates (KB5005010) as the CVE-2021-34527 (PrintNightmare) mitigation. A system with no such GPO override relies on that shipped default (elevation required) and is not flagged.",
		types.SeverityHigh, count, nil)
}

// v3.1.21 dedup - PA038_ZEROLOGON_ENFORCEMENT_OFF removed (same key as
// custom ZEROLOGON_PATCH_ENFORCEMENT). Mapping migrated in mappings.go.

// --- PA038-15: NetCease / Net session hardening off ---

type PA038NetSessionHardeningDetector struct{ audit.BaseDetector }

func NewPA038NetSessionHardeningDetector() *PA038NetSessionHardeningDetector {
	return &PA038NetSessionHardeningDetector{BaseDetector: audit.NewBaseDetector("PA038_NET_SESSION_HARDENING_OFF", audit.CategoryCompliance)}
}
func (d *PA038NetSessionHardeningDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// NetSessionHardening restricts who can enumerate Net Sessions (SrvsvcSessionInfo).
	// Non-nil and > 0 = a DWORD-style value is set at that registry path.
	//
	// Two fixes.
	//  1. No ANSSI document (PA-099, PB-090, or the general ANSSI corpus)
	//     mentions NetCease, SrvsvcSessionInfo, or NetSessionEnum hardening
	//     at all - "ANSSI PA-038" was fabricated (see package comment
	//     above). Retagged as a product-defined heuristic with no framework
	//     attribution.
	//  2. Structurally narrow, causing a false positive on every domain
	//     hardened via the real technique: NetCease sets a
	//     security-descriptor (REG_BINARY SDDL) ACL at
	//     LanmanServer\DefaultSecurity\SrvsvcSessionInfo, or is applied
	//     outside Group Policy entirely (a logon script / manual registry
	//     edit) - registrypol_parser.go only recognizes a DWORD value at
	//     that same path (getDWORDValue, registrypol_parser.go:320), which
	//     is not what the real mitigation writes there. A domain hardened
	//     the standard way parses as unset (nil) every time, so this can
	//     only detect a non-standard DWORD-style convention, never the
	//     actual mitigation - "not hardened" is not a safe conclusion from
	//     this signal. Lowered to Info and reworded accordingly.
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
	return wrapFinding(d, "NetCease : aucun réglage DWORD de restriction des sessions réseau détecté",
		"No GPO sets a DWORD-style value at LanmanServer\\DefaultSecurity\\SrvsvcSessionInfo. This is a product-defined heuristic, not an ANSSI requirement (no ANSSI document covering NetCease/SrvsvcSessionInfo hardening was found). It is also narrow: the real NetCease mitigation applies a security-descriptor (REG_BINARY) ACL at this same registry path, or is applied outside Group Policy entirely - neither is visible to this DWORD-only check, so a domain hardened via the standard method will still show this finding. Treat as 'no simple registry toggle observed', not a confirmed absence of NetCease.",
		types.SeverityInfo, count, nil)
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
