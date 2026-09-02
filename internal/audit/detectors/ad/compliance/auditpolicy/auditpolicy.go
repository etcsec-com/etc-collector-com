// Package auditpolicy resolves the Advanced Audit Policy Configuration
// (audit.csv) subcategory settings that ANSSI_R4_LOGGING, DISA_AUDIT_POLICIES
// and NIST_AU_2_AUDIT_EVENTS need (T_132/D3).
//
// Some of those detectors' checks name one specific audit subcategory (e.g.
// DISA V-63455 "Logon/Logoff (Logon)" is really about the "Logon"
// subcategory, not the whole Logon/Logoff category), which the legacy
// [Event Audit] section of GptTmpl.inf cannot distinguish — it only has one
// value per basic 9-category rollup. When a GPO's audit.csv configures that
// subcategory directly, its value is authoritative for that check; the
// legacy category-level value is used only as a fallback for checks with no
// single matching subcategory.
package auditpolicy

import (
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// Subcategory GUIDs are stable across Windows versions (Microsoft's
// Advanced Audit Policy Configuration reference). Confirmed against DC01
// evidence in
// docs/security-validation/results/t128-croise/plant-t128-gptmpl-and-advaudit.ps1.
const (
	CredentialValidation      = "{0cce923f-69ae-11d9-bed3-505054503030}"
	KerberosAuthenticationSvc = "{0cce9242-69ae-11d9-bed3-505054503030}"
	UserAccountManagement     = "{0cce9235-69ae-11d9-bed3-505054503030}"
	SecurityGroupManagement   = "{0cce9237-69ae-11d9-bed3-505054503030}"
	DirectoryServiceAccess    = "{0cce923b-69ae-11d9-bed3-505054503030}"
	Logon                     = "{0cce9215-69ae-11d9-bed3-505054503030}"
	ProcessCreation           = "{0cce922b-69ae-11d9-bed3-505054503030}"
	AuditPolicyChange         = "{0cce922f-69ae-11d9-bed3-505054503030}"
	SensitivePrivilegeUse     = "{0cce9228-69ae-11d9-bed3-505054503030}"
	SecurityStateChange       = "{0cce9210-69ae-11d9-bed3-505054503030}"
)

// Well-known default GPO GUIDs (duplicated from
// internal/audit/helpers.DefaultDomainPolicyGUID/DefaultDCPolicyGUID rather
// than imported: this package deliberately doesn't take a dependency on
// helpers, which detectors/azure also imports).
const (
	defaultDomainPolicyGUID = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
	defaultDCPolicyGUID     = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"
)

// GetAdvancedAudit returns the audit.csv subcategory map from a GPO, using
// the same precedence as helpers.GetEventAudit (DC policy, then Domain
// policy, then any GPO that has one) so the two sources are looked up
// consistently.
func GetAdvancedAudit(policies map[string]*audit.GPOPolicy) map[string]int {
	var domain, dc map[string]int
	for guid, p := range policies {
		if p == nil || p.AdvancedAudit == nil {
			continue
		}
		switch {
		case strings.EqualFold(guid, defaultDCPolicyGUID):
			dc = p.AdvancedAudit
		case strings.EqualFold(guid, defaultDomainPolicyGUID):
			domain = p.AdvancedAudit
		}
	}
	if dc != nil {
		return dc
	}
	if domain != nil {
		return domain
	}
	for _, p := range policies {
		if p != nil && p.AdvancedAudit != nil {
			return p.AdvancedAudit
		}
	}
	return nil
}

// Level resolves the effective 0-3 audit setting for one check: the
// subcategory's audit.csv value when a GPO configures it directly (the
// authoritative, granular source); otherwise the legacy [Event Audit]
// category-level value read from ea via legacy, but only when at least one
// GPO has an [Event Audit] section at all (ea != nil) — its total absence is
// not evidence that nothing is audited (T_128 disproved that on DC01:
// auditpol showed active auditing configured entirely outside of Group
// Policy). legacy is only invoked when ea != nil, so callers can pass a
// closure over ea's fields without a nil check of their own. ok is false
// when neither source has anything to say, in which case the caller must
// not count the check as a violation.
func Level(adv map[string]int, subcategoryGUID string, ea *audit.EventAudit, legacy func(*audit.EventAudit) int) (value int, ok bool) {
	if adv != nil {
		if v, present := adv[subcategoryGUID]; present {
			return v, true
		}
	}
	if ea != nil {
		return legacy(ea), true
	}
	return 0, false
}
