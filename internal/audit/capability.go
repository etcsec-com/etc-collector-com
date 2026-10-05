package audit

import "sort"

// Collection capabilities and the consent gate.
//
// The collector is agentless and low-privilege by default: it reads Active
// Directory over LDAP and Group Policy files over the SYSVOL share, both of
// which any authenticated domain user can do. A few detectors need more than
// that - for example reading a domain controller's or a CA's registry, which
// requires administrator-equivalent rights on those hosts. Collecting anything
// beyond the low-privilege baseline is an explicit, operator-granted escalation.
//
// A Capability names one class of collection access. The consent gate below
// decides, per detector, whether the operator has granted the access that
// detector needs - and, unlike the provider gate, it is fail-closed: a detector
// that needs a non-baseline capability runs only when that capability has been
// explicitly granted.

// Capability is a class of data-collection access the collector may use.
type Capability string

const (
	// CapLDAP is directory read over LDAP. Baseline, always available.
	CapLDAP Capability = "ldap"
	// CapSysvol is reading Group Policy files on the SYSVOL share. Baseline:
	// any authenticated domain user can read SYSVOL.
	CapSysvol Capability = "sysvol"
	// CapRemoteRegistry is reading a remote host's registry (domain
	// controllers and the CA) over MS-RRP. An escalation: it needs
	// administrator-equivalent rights on the target host, so it is never used
	// without explicit consent.
	CapRemoteRegistry Capability = "remote_registry"
)

// baselineCapabilities are granted without any consent - the agentless,
// low-privilege floor every audit starts from.
var baselineCapabilities = map[Capability]bool{
	CapLDAP:   true,
	CapSysvol: true,
}

// detectorCapability maps a detector ID to the capability it needs BEYOND the
// baseline. A detector absent from this table needs only the baseline.
//
// This is an explicit allow-list of escalations, never inferred: a new detector
// defaults to the baseline and can never silently acquire an escalated
// capability. Adding an entry here is the single, reviewable place where a
// detector is declared to need elevated access.
//
// The CapSysvol entries below are every detector whose verdict is built
// EXCLUSIVELY from data.GPOPolicies and/or data.SYSVOLFindings - SYSVOL-parsed
// data with no other source. Each is read from
// internal/audit/detectors/ad/**, and the comment on each entry cites the
// exact line that shows the dependency: either a bare `range data.GPOPolicies`
// / `range data.SYSVOLFindings` loop, or a call into a helper
// (helpers.FindRegistrySettingInt/String, helpers.FindPrivilegeRight,
// helpers.GetEventAudit/GetKerberosPolicy, auditpolicy.GetAdvancedAudit /
// .Level via the monitoring package's advancedAuditLevel) that itself takes
// only data.GPOPolicies and nothing else. A detector that ALSO reads another
// data source (LDAP GPO/group/user data, ACLs, trusts, ...) and can still
// reach a real, if narrower, verdict without SYSVOL is deliberately left out
// - see GPO_ORPHANED, GPO_PASSWORD_IN_SYSVOL and CIS_NETWORK_SECURITY for
// examples of that shape.
//
// Two detectors here (KERBEROS_RENEWABLE_TICKET_LONG,
// KERBEROS_TICKET_LIFETIME_LONG) also read a DomainInfo.MaxRenewAge/
// MaxTicketAge fallback in their own source, but that field is never
// assigned by any provider in this codebase today (see the comment on
// weak-kerberos-policy.go's Detect) - so in the CURRENT wiring the SYSVOL
// path is the only one that can ever fire. If a future change populates
// those DomainInfo fields, these three entries need re-reading, not blind
// removal.
var detectorCapability = map[string]Capability{
	// --- gpo/*: registry.pol / GptTmpl.inf settings parsed from SYSVOL. No
	// LDAP attribute carries these values, so there is nothing to fall back
	// to; each Detect() reads data.GPOPolicies alone via
	// helpers.FindRegistrySettingInt/String or helpers.FindPrivilegeRight.
	"BITLOCKER_NOT_REQUIRED":             CapSysvol, // gpo/bitlocker-not-required.go:32
	"CACHED_LOGONS_EXCESSIVE":            CapSysvol, // gpo/cached-logons-excessive.go:56
	"CREDENTIAL_GUARD_DISABLED":          CapSysvol, // gpo/credential-guard-disabled.go:41-46
	"DEFENDER_ASR_NOT_CONFIGURED":        CapSysvol, // gpo/defender-asr.go:32
	"FIREWALL_OUTBOUND_NOT_BLOCKED":      CapSysvol, // gpo/firewall-outbound.go:32
	"FOLDER_OPTIONS_SCRIPT_NOT_HARDENED": CapSysvol, // gpo/folder-options-not-hardened.go:33-47
	"GPO_FOLDER_OPTIONS_SCRIPT_EXEC":     CapSysvol, // gpo/folder-options-script-exec.go:47-67
	"HARDENED_UNC_PATHS_WEAK":            CapSysvol, // gpo/hardened-unc-paths.go:35,42
	"KERBEROS_ARMORING_CLIENT_DISABLED":  CapSysvol, // gpo/kerberos-armoring-client-disabled.go:32
	"KERBEROS_ARMORING_DC_DISABLED":      CapSysvol, // gpo/kerberos-armoring-dc-disabled.go:32
	"GPO_LLMNR_NOT_DISABLED":             CapSysvol, // gpo/llmnr-not-disabled.go:32
	"LSA_PROTECTION_DISABLED":            CapSysvol, // gpo/lsa-protection-disabled.go:32
	"NET_SESSION_HARDENING_MISSING":      CapSysvol, // gpo/net-session-hardening.go:47
	"NTLMV1_ALLOWED":                     CapSysvol, // gpo/ntlmv1-allowed.go:32
	"PRINTNIGHTMARE_VULNERABLE":          CapSysvol, // gpo/printnightmare-vulnerable.go:32
	"PRIVILEGE_SEBACKUP_ABUSE":           CapSysvol, // gpo/privilege-sebackup-abuse.go:32
	"PRIVILEGE_SEDEBUG_ABUSE":            CapSysvol, // gpo/privilege-sedebug-abuse.go:52
	"PRIVILEGE_SELOADDRIVER_ABUSE":       CapSysvol, // gpo/privilege-seloaddriver-abuse.go:32
	"PRIVILEGE_SERESTORE_ABUSE":          CapSysvol, // gpo/privilege-serestore-abuse.go:32
	"PRIVILEGE_SETCB_ABUSE":              CapSysvol, // gpo/privilege-setcb-abuse.go:32
	"SAM_REMOTE_ACCESS_OPEN":             CapSysvol, // gpo/sam-remote-access-open.go:33
	"TERMINAL_SERVICES_NOT_HARDENED":     CapSysvol, // gpo/terminal-services.go:35,43
	"WDIGEST_ENABLED":                    CapSysvol, // gpo/wdigest-enabled.go:32
	"WSUS_HTTP_USED":                     CapSysvol, // gpo/wsus-http-used.go:33
	"ZEROLOGON_PATCH_ENFORCEMENT":        CapSysvol, // gpo/zerologon-patch-enforcement.go:32

	// --- advanced/*: same GPOPolicies-only shape, outside the gpo/ package.
	"WEAK_KERBEROS_POLICY":          CapSysvol, // advanced/domain-policy/weak-kerberos-policy.go:45 (DomainInfo fallback dead, see comment above)
	"AUDIT_POLICY_WEAK":             CapSysvol, // advanced/monitoring/audit-policy-weak.go:57-58
	"POWERSHELL_LOGGING_DISABLED":   CapSysvol, // advanced/monitoring/powershell-logging-disabled.go:34-39
	"DELEGATION_PRIVILEGE":          CapSysvol, // advanced/other/delegation-privilege.go:49
	"NTLM_RELAY_OPPORTUNITY":        CapSysvol, // advanced/other/ntlm-relay-opportunity.go:41,45-50
	"LDAP_CHANNEL_BINDING_DISABLED": CapSysvol, // advanced/signing/ldap-channel-binding-disabled.go:42,47
	"LDAP_SIGNING_DISABLED":         CapSysvol, // advanced/signing/ldap-signing-disabled.go:40,45
	"SMB_SIGNING_DISABLED":          CapSysvol, // advanced/signing/smb-signing-disabled.go:43,48
	"SMB_V1_ENABLED":                CapSysvol, // advanced/signing/smb-v1-enabled.go:34

	// --- compliance/anssi/*: ANSSI-mapped checks that are, underneath the
	// citation, the same GPOPolicies-only or SYSVOLFindings-only shape.
	"BP039_VBS_OFF":                        CapSysvol, // compliance/anssi/bp039_phase_c.go:67
	"BP039_HVCI_OFF":                       CapSysvol, // compliance/anssi/bp039_phase_c.go:86
	"BP039_HVCI_NO_UEFI_LOCK":              CapSysvol, // compliance/anssi/bp039_phase_c.go:105
	"BP039_CRED_GUARD_LIMITED_SCOPE":       CapSysvol, // compliance/anssi/bp039_phase_c.go:144
	"BP039_CRED_GUARD_NO_UEFI_LOCK":        CapSysvol, // compliance/anssi/bp039_phase_c.go:180
	"BP039_CCI_NOT_DEPLOYED":               CapSysvol, // compliance/anssi/bp039_phase_c.go:234-238
	"BP039_PRIV_ACCOUNTS_CACHED":           CapSysvol, // compliance/anssi/bp039_phase_c.go:263-274
	"M29_LOCAL_ADMIN_NOT_RESTRICTED":       CapSysvol, // compliance/anssi/m29_local_admin.go:39,86-96
	"PA038_RDP_NLA_NOT_REQUIRED":           CapSysvol, // compliance/anssi/pa038_windows_hardening.go:37-47
	"PA038_RDP_SECURITY_LAYER_WEAK":        CapSysvol, // compliance/anssi/pa038_windows_hardening.go:70-74
	"PA038_PS_SCRIPTBLOCK_LOGGING_OFF":     CapSysvol, // compliance/anssi/pa038_windows_hardening.go:97-101
	"PA038_PS_MODULE_LOGGING_OFF":          CapSysvol, // compliance/anssi/pa038_windows_hardening.go:124-128
	"PA038_PS_TRANSCRIPTION_OFF":           CapSysvol, // compliance/anssi/pa038_windows_hardening.go:151-155
	"PA038_WSUS_NOT_CONFIGURED":            CapSysvol, // compliance/anssi/pa038_windows_hardening.go:190-194
	"PA038_POINT_AND_PRINT_ELEVATION_OFF":  CapSysvol, // compliance/anssi/pa038_windows_hardening.go:235-239
	"PA038_NET_SESSION_HARDENING_OFF":      CapSysvol, // compliance/anssi/pa038_windows_hardening.go:286-290
	"ANSSI_R79_RDP_NOT_HARDENED":           CapSysvol, // compliance/anssi/phase_d_detectors.go:365-376
	"ANSSI_R82_R83_ADMIN_ARCHITECTURE":     CapSysvol, // compliance/anssi/phase_d_detectors.go:449-460
	"ANSSI_R23_LM_HASH_NOT_DISABLED":       CapSysvol, // compliance/anssi/r16_to_r27_privileges_crypto.go:91-98
	"ANSSI_R27_KERBEROS_PREAUTH_NOT_FAST":  CapSysvol, // compliance/anssi/r16_to_r27_privileges_crypto.go:118-127
	"ANSSI_R31_SCRIPT_SECRETS":             CapSysvol, // compliance/anssi/r31_script_secrets.go:31 (SYSVOLFindings, not GPOPolicies)
	"ANSSI_R38_ADVANCED_AUDIT_NOT_ENABLED": CapSysvol, // compliance/anssi/r34_to_r39_hardening.go:81-111
	"ANSSI_R39_SECURITY_LOG_TOO_SMALL":     CapSysvol, // compliance/anssi/r34_to_r39_hardening.go:135-152
	"ANSSI_R4_LOGGING":                     CapSysvol, // compliance/anssi/r4-logging.go:72-74
	"ANSSI_R73_NTLM_OUTBOUND_TIER0":        CapSysvol, // compliance/anssi/r73_r74_ntlm_outbound.go:62-69
	"ANSSI_R74_NTLM_OUTBOUND_DOMAIN":       CapSysvol, // compliance/anssi/r73_r74_ntlm_outbound.go:130-136
	"ANSSI_R34_2_RESTRICT_REMOTE_SAM_OFF":  CapSysvol, // compliance/anssi/sub_recos.go:314-320

	// --- compliance/cis, disa, hds, nist: one detector each - the rest of
	// these packages' detectors read LDAP/ACL data or are purely
	// informational, and are deliberately NOT listed (see comment above).
	"CIS_USER_RIGHTS":                   CapSysvol, // compliance/cis/user-rights.go:43-48
	"DISA_AUDIT_POLICIES":               CapSysvol, // compliance/disa/audit-policies.go:64-65
	"HDS_5_4_LOG_ACCESS_TO_HEALTH_DATA": CapSysvol, // compliance/hds/hds_detectors.go:101-109
	"NIST_AU_2_AUDIT_EVENTS":            CapSysvol, // compliance/nist/au2-audit-events.go:63-64

	// --- kerberos/*: domain Kerberos policy is parsed from SYSVOL
	// (GptTmpl.inf); see the DomainInfo-fallback note above.
	"KERBEROS_RENEWABLE_TICKET_LONG": CapSysvol, // kerberos/kerberos-renewable-ticket-long.go:55
	"KERBEROS_TICKET_LIFETIME_LONG":  CapSysvol, // kerberos/kerberos-ticket-lifetime-long.go:37

	// --- monitoring/*: all six resolve exclusively through
	// advancedAuditLevel(data, ...), which itself only ever reads
	// data.GPOPolicies (auditpolicy.GetAdvancedAudit + helpers.GetEventAudit)
	// - see advanced-audit.go:21-25. Each already declines to call its result
	// a violation when unmeasured (ok==false), but that self-restraint can't
	// tell "SYSVOL refused" apart from "SYSVOL reachable, nothing configured
	// through Group Policy": excluding them from selection is what makes that
	// distinction, not their own internal guard.
	"SECURITY_LOG_SIZE_SMALL":      CapSysvol, // monitoring/security-log-size.go:38
	"AUDIT_ACCOUNT_MGMT_DISABLED":  CapSysvol, // monitoring/audit-account-mgmt.go:34
	"AUDIT_LOGON_EVENTS_DISABLED":  CapSysvol, // monitoring/audit-logon-events.go:37-40
	"AUDIT_POLICY_CHANGE_DISABLED": CapSysvol, // monitoring/audit-policy-change.go:34
	"AUDIT_PRIVILEGE_USE_DISABLED": CapSysvol, // monitoring/audit-privilege-use.go:34
	"DC_AUDIT_POLICY_INCOMPLETE":   CapSysvol, // monitoring/dc-audit-policy-incomplete.go:53
}

// RequiredCapability returns the capability a detector needs to run. Detectors
// not listed in detectorCapability need only the LDAP baseline.
func RequiredCapability(id string) Capability {
	if c, ok := detectorCapability[id]; ok {
		return c
	}
	return CapLDAP
}

// SysvolDependentDetectors returns the sorted IDs of every detector listed in
// detectorCapability against CapSysvol - the detectors that disappear from
// selection when the operator refuses SYSVOL. Exported for the
// CAPABILITY_REFUSED_SYSVOL warning built in engine.go's Run, and for the
// collection-consent tests that prove the exclusion actually happens.
func SysvolDependentDetectors() []string {
	ids := make([]string, 0, len(detectorCapability))
	for id, c := range detectorCapability {
		if c == CapSysvol {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// sysvolRefusalDetail compares the detectors that would have run had SYSVOL
// not been refused (wouldHaveRun) against what actually ran (actual, the
// same selection with the refusal applied), and returns the IDs present in
// the former but not the latter, plus both counts. Both slices must come
// from selecting over the SAME RunOptions (categories, detector IDs,
// excludes) - only the SYSVOL consent differs between them - so the
// difference reflects exactly what the refusal removed, not a change in
// audit scope.
func sysvolRefusalDetail(wouldHaveRun, actual []Detector) (affected []string, total, remaining int) {
	actualSet := make(map[string]bool, len(actual))
	for _, d := range actual {
		actualSet[d.ID()] = true
	}
	for _, d := range wouldHaveRun {
		if !actualSet[d.ID()] {
			affected = append(affected, d.ID())
		}
	}
	sort.Strings(affected)
	return affected, len(wouldHaveRun), len(actual)
}

// consentGate decides whether a detector may run given the capabilities the
// operator has explicitly granted. Unlike providerGate it is FAIL-CLOSED: a
// detector that needs a non-baseline capability runs only when that capability
// is in the granted set. Baseline capabilities are always allowed, so an audit
// with no granted escalations still runs every baseline detector.
type consentGate struct {
	granted map[Capability]bool
}

// newConsentGate builds a gate from the operator-granted escalations. Baseline
// capabilities are always added, so the zero grant still allows every baseline
// detector.
func newConsentGate(granted []Capability) consentGate {
	g := consentGate{granted: make(map[Capability]bool, len(baselineCapabilities)+len(granted))}
	for c := range baselineCapabilities {
		g.granted[c] = true
	}
	for _, c := range granted {
		g.granted[c] = true
	}
	return g
}

// allows reports whether the detector's required capability has been granted.
// Fail-closed: a required escalation that is not in the granted set denies the
// detector.
func (g consentGate) allows(d Detector) bool {
	return g.allowsID(d.ID())
}

// allowsID is allows keyed by detector ID, so the gate can be exercised without
// a Detector value.
func (g consentGate) allowsID(id string) bool {
	return g.granted[RequiredCapability(id)]
}

// newConsentGateWithDenials builds a gate from what the operator granted AND
// what the operator explicitly refused. Refusal wins over the baseline: this is
// the downgrade path - an operator who does not want the collector reading
// SYSVOL says so once, and the collector then never reads it, on any run.
//
// Order matters and is deliberate: baseline, then grants, then denials last.
// A denial can therefore remove a baseline capability AND an escalation the
// same configuration granted, and no ordering of the two lists can produce a
// grant that overrides a refusal.
func newConsentGateWithDenials(granted, denied []Capability) consentGate {
	g := newConsentGate(granted)
	for _, c := range denied {
		delete(g.granted, c)
	}
	return g
}

// permits reports whether a COLLECTION step needing this capability may run.
//
// This is the barrier that matters. The detector-selection gate only decides
// what is analysed; by the time it runs, collection has already happened. A
// capability the operator refused must never be exercised in the first place -
// a collector that reads what it was told not to read is indefensible,
// whatever it does with the result afterwards. Every collection step that
// needs more than the LDAP baseline asks this question before acting.
func (g consentGate) permits(need Capability) bool {
	return g.granted[need]
}
