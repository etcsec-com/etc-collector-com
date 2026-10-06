package monitoring

import (
	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/auditpolicy"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
)

// advancedAuditLevel resolves the effective 0-3 setting for one audit
// category: the Advanced Audit Policy Configuration (audit.csv) value for
// subcategoryGUID when a GPO configures it directly - Windows treats the
// subcategory setting as authoritative over the legacy category once set -
// falling back to the legacy [Event Audit] category value (via legacy) only
// when no GPO's audit.csv configures that subcategory.
//
// ok is false when neither source has anything to say for this category. A
// domain's effective audit policy is very often managed outside of Group
// Policy entirely (local secedit/auditpol.exe, non-domain tooling), so that
// case must not be read as "auditing is disabled" - callers must not count
// it as a violation.
func advancedAuditLevel(data *audit.DetectorData, subcategoryGUID string, legacy func(*audit.EventAudit) int) (value int, ok bool) {
	adv := auditpolicy.GetAdvancedAudit(data.GPOPolicies)
	ea := helpers.GetEventAudit(data.GPOPolicies)
	return auditpolicy.Level(adv, subcategoryGUID, ea, legacy)
}

// notConfiguredViaGPO is the honest detail payload for a category that no
// GPO configures through either audit source: it records what is known
// (nothing at the GPO layer) without asserting the machine itself has no
// auditing, since that may be configured outside of Group Policy.
func notConfiguredViaGPO() map[string]interface{} {
	return map[string]interface{}{
		"status": "Not configured via any Group Policy (neither Advanced Audit Policy Configuration nor the legacy Audit Policy). This does not necessarily mean auditing is disabled on the endpoint - it may be configured outside of Group Policy.",
	}
}
