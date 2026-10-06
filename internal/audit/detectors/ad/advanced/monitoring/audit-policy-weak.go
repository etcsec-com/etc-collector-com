package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/auditpolicy"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AuditPolicyWeakDetector detects weak or incomplete audit policies
type AuditPolicyWeakDetector struct {
	audit.BaseDetector
}

// NewAuditPolicyWeakDetector creates a new detector
func NewAuditPolicyWeakDetector() *AuditPolicyWeakDetector {
	return &AuditPolicyWeakDetector{
		BaseDetector: audit.NewBaseDetector("AUDIT_POLICY_WEAK", audit.CategoryAdvanced),
	}
}

// legacyCategoryNames are the 9-category [Event Audit] rollup this detector
// evaluates when no finer-grained data is available.
var legacyCategoryNames = []string{
	"AuditAccountLogon", "AuditAccountManage", "AuditLogonEvents",
	"AuditObjectAccess", "AuditPolicyChange", "AuditPrivilegeUse", "AuditSystemEvents",
}

// Detect executes the detection.
//
// Source: Microsoft Learn, "Basic audit policy settings vs. advanced audit
// policy configuration settings" - Microsoft has recommended Advanced Audit
// Policy Configuration (audit.csv, parsed by
// internal/providers/smb/audit_csv_parser.go into GPOPolicy.AdvancedAudit)
// over the legacy [Event Audit] rollup since Windows Server 2008 R2
// (learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/
// security-best-practices/basic-audit-policy-settings-vs--advanced-audit-policy-configuration-settings).
//
// A prior version only ever read [Event Audit] and returned an
// empty, "compliant" finding whenever ea == nil - which is also true of a
// domain that audits correctly through Advanced Audit Policy alone and
// never touches the legacy section. It could not tell "nothing configured"
// apart from "configured the modern way", and silently called both
// compliant.
func (d *AuditPolicyWeakDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Weak Audit Policy Configuration",
		Description: "Critical audit categories are not configured for both Success and Failure, reducing visibility into security events.",
		Count:       0,
	}

	ea := helpers.GetEventAudit(data.GPOPolicies)
	adv := auditpolicy.GetAdvancedAudit(data.GPOPolicies)

	if ea == nil {
		if len(adv) == 0 {
			// Neither mechanism is configured by any GPO anywhere in the
			// domain: this is the worst case (no audit evidence at all),
			// not the silent "0 weak categories" the old code returned for
			// it.
			finding.Severity = types.SeverityCritical
			finding.Count = len(legacyCategoryNames)
			finding.Details = map[string]interface{}{
				"weakCategories": legacyCategoryNames,
				"totalChecked":   len(legacyCategoryNames),
				"recommendation": "No audit policy (legacy or advanced) is configured by any GPO. Configure Advanced Audit Policy Configuration for Success and Failure on the critical categories.",
			}
			return []types.Finding{finding}
		}
		// Advanced Audit Policy is deployed (the modern, Microsoft-recommended
		// mechanism) but this detector's 7-category legacy rollup has no
		// reliable 1:1 subcategory mapping to evaluate it against - each
		// legacy category rolls up several audit.csv subcategories, and
		// claiming "0 weak categories" here would silently assert a
		// verification this detector cannot actually perform. Say so
		// instead of implying compliance was checked.
		finding.Details = map[string]interface{}{
			"note": "Advanced Audit Policy Configuration (audit.csv) is deployed but this detector only evaluates the legacy [Event Audit] rollup; subcategory-level completeness was not verified.",
		}
		return []types.Finding{finding}
	}

	// Check all critical categories (3 = Success+Failure)
	type auditCheck struct {
		name  string
		value int
	}
	checks := []auditCheck{
		{"AuditAccountLogon", ea.AuditAccountLogon},
		{"AuditAccountManage", ea.AuditAccountManage},
		{"AuditLogonEvents", ea.AuditLogonEvents},
		{"AuditObjectAccess", ea.AuditObjectAccess},
		{"AuditPolicyChange", ea.AuditPolicyChange},
		{"AuditPrivilegeUse", ea.AuditPrivilegeUse},
		{"AuditSystemEvents", ea.AuditSystemEvents},
	}

	var weakCategories []string
	for _, c := range checks {
		if c.value < 3 {
			weakCategories = append(weakCategories, c.name)
		}
	}

	if len(weakCategories) > 0 {
		finding.Count = len(weakCategories)
		finding.Details = map[string]interface{}{
			"weakCategories": weakCategories,
			"totalChecked":   len(checks),
			"recommendation": "Enable all critical audit categories for both Success and Failure in Advanced Audit Policy Configuration.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAuditPolicyWeakDetector())
}
