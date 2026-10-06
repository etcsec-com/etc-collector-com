package disa

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/auditpolicy"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AuditPoliciesDetector checks DISA STIG audit policy compliance
type AuditPoliciesDetector struct {
	audit.BaseDetector
}

// NewAuditPoliciesDetector creates a new detector
func NewAuditPoliciesDetector() *AuditPoliciesDetector {
	return &AuditPoliciesDetector{
		BaseDetector: audit.NewBaseDetector("DISA_AUDIT_POLICIES", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *AuditPoliciesDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "DISA STIG Audit Policies Non-Compliant",
		Description: "Audit policies do not meet DISA STIG requirements for Windows Server.",
		Count:       0,
		Details: map[string]interface{}{
			"framework": "DISA",
			"stig":      "Windows Server STIG",
		},
	}

	// Every one of these STIG vuln IDs actually names one specific
	// Advanced Audit Policy subcategory (the parenthetical), not the whole
	// legacy category - GptTmpl.inf's [Event Audit] can't tell "Logon" from
	// "Logoff" within "Logon/Logoff", for example. Each check therefore
	// prefers the subcategory's audit.csv value when a GPO configures it,
	// falling back to the legacy category-level value only when at least
	// one GPO has an [Event Audit] section at all. An earlier version had instead
	// substituted an all-zero EventAudit whenever [Event Audit] was absent
	// everywhere, on the assumption that meant "nothing audited" - disproved
	// on DC01, which audits actively but entirely outside of Group Policy
	// (docs/security-validation/results/t128-croise/METHODE-ET-VERDICTS.md).
	// Absence of GPO evidence is no longer treated as evidence of a
	// violation: a check with neither source is skipped, not maximized.
	//
	// The V-634xx IDs below were the wrong STIG entirely - that
	// range is the Windows 10 (client) STIG, not a Windows Server STIG, the
	// same root cause already fixed for the sibling DISA_ACCOUNT_POLICIES
	// detector (account-policies.go). This is a domain-wide audit
	// policy, so the applicable STIG is Microsoft Windows Server 2022
	// (V2R8); replaced with its real, verified rule/Vuln IDs. Two of the
	// seven thresholds were also wrong, independent of the ID swap:
	// Security Group Management only requires Success (was requiring Both),
	// and Sensitive Privilege Use requires Both (was requiring only
	// Failure, min=2) - both corrected below. Process Creation and Security
	// State Change were already correctly Success-only.
	ea := helpers.GetEventAudit(data.GPOPolicies)
	adv := auditpolicy.GetAdvancedAudit(data.GPOPolicies)

	type stigCheck struct {
		vulnID   string
		category string
		guid     string
		legacy   func(*audit.EventAudit) int
		min      int
	}
	checks := []stigCheck{
		{"WN22-AU-000070/000080 (V-254300/V-254301)", "Account Logon (Credential Validation)", auditpolicy.CredentialValidation, func(e *audit.EventAudit) int { return e.AuditAccountLogon }, 3},
		{"WN22-AU-000100 (V-254303)", "Account Management (Security Group Management)", auditpolicy.SecurityGroupManagement, func(e *audit.EventAudit) int { return e.AuditAccountManage }, 1},
		{"WN22-AU-000140 (V-254307)", "Detailed Tracking (Process Creation)", auditpolicy.ProcessCreation, func(e *audit.EventAudit) int { return e.AuditProcessTracking }, 1},
		{"WN22-AU-000190/000200 (V-254312/V-254313)", "Logon/Logoff (Logon)", auditpolicy.Logon, func(e *audit.EventAudit) int { return e.AuditLogonEvents }, 3},
		{"WN22-AU-000260/000270 (V-254319/V-254320)", "Policy Change (Audit Policy Change)", auditpolicy.AuditPolicyChange, func(e *audit.EventAudit) int { return e.AuditPolicyChange }, 3},
		{"WN22-AU-000300/000310 (V-254323/V-254324)", "Privilege Use (Sensitive Privilege Use)", auditpolicy.SensitivePrivilegeUse, func(e *audit.EventAudit) int { return e.AuditPrivilegeUse }, 3},
		{"WN22-AU-000360 (V-254329)", "System (Security State Change)", auditpolicy.SecurityStateChange, func(e *audit.EventAudit) int { return e.AuditSystemEvents }, 1},
	}

	var failures []string
	for _, c := range checks {
		v, ok := auditpolicy.Level(adv, c.guid, ea, c.legacy)
		if !ok {
			continue
		}
		if v < c.min {
			failures = append(failures, c.vulnID+": "+c.category)
		}
	}

	if len(failures) > 0 {
		finding.Count = len(failures)
		finding.Details["failingSTIGs"] = failures
		finding.Details["recommendation"] = "Configure the named audit subcategories to 'Success and Failure' via Group Policy - either legacy Audit Policy or Advanced Audit Policy Configuration (audit.csv); both are read."
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAuditPoliciesDetector())
}
