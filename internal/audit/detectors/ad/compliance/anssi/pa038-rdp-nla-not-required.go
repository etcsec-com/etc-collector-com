package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PA-038 group: Recommandations de sécurité pour les systèmes Windows (ANSSI PA-038).
//
// "ANSSI PA-038" is not a real ANSSI document reference - verified
// against ANSSI's own published catalog, no such reference code exists. This
// salve only re-verified and fixed the citation/logic for
// PA038_NET_SESSION_HARDENING_OFF and PA038_POINT_AND_PRINT_ELEVATION_OFF
// (see their own files for what was actually checked and what the real
// sources are, where one exists). The "PA-038" attribution on the other
// detectors in this group has NOT been re-verified in this salve and may be
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

func init() {
	audit.MustRegister(NewPA038RDPNLADetector())
}
