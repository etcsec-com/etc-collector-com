package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/auditpolicy"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DCAuditPolicyIncompleteDetector checks if the DC audit policy covers all critical categories
type DCAuditPolicyIncompleteDetector struct {
	audit.BaseDetector
}

func NewDCAuditPolicyIncompleteDetector() *DCAuditPolicyIncompleteDetector {
	return &DCAuditPolicyIncompleteDetector{
		BaseDetector: audit.NewBaseDetector("DC_AUDIT_POLICY_INCOMPLETE", audit.CategoryMonitoring),
	}
}

func (d *DCAuditPolicyIncompleteDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Domain Controller Audit Policy Incomplete",
		Description: "The audit policy applied to Domain Controllers does not log both success and failure events for all critical security categories. Incomplete audit policies create blind spots that attackers exploit to operate undetected.",
		Count:       0,
	}

	// Each critical category is resolved against its Advanced Audit Policy
	// subcategory first, falling back to the legacy [Event Audit] category
	// only when no GPO's audit.csv configures that subcategory.
	type category struct {
		name            string
		subcategoryGUID string
		legacy          func(*audit.EventAudit) int
		minimum         int // required value (3 = Success+Failure, 2 = at least Failure)
	}
	categories := []category{
		{"Account Logon", auditpolicy.CredentialValidation, func(e *audit.EventAudit) int { return e.AuditAccountLogon }, 3},
		{"Account Management", auditpolicy.UserAccountManagement, func(e *audit.EventAudit) int { return e.AuditAccountManage }, 3},
		{"Logon Events", auditpolicy.Logon, func(e *audit.EventAudit) int { return e.AuditLogonEvents }, 3},
		{"Policy Change", auditpolicy.AuditPolicyChange, func(e *audit.EventAudit) int { return e.AuditPolicyChange }, 3},
		{"System Events", auditpolicy.SecurityStateChange, func(e *audit.EventAudit) int { return e.AuditSystemEvents }, 3},
		{"Directory Service Access", auditpolicy.DirectoryServiceAccess, func(e *audit.EventAudit) int { return e.AuditDSAccess }, 2},
	}

	issues := []string{}
	measured := 0
	for _, c := range categories {
		value, ok := advancedAuditLevel(data, c.subcategoryGUID, c.legacy)
		if !ok {
			// Neither audit.csv nor [Event Audit] configures this category
			// via GPO - not evidence of a gap, so it is excluded rather than
			// counted as a violation.
			continue
		}
		measured++
		if value < c.minimum {
			if c.minimum == 3 {
				issues = append(issues, c.name+": not logging both success and failure")
			} else {
				issues = append(issues, c.name+": failure auditing not enabled")
			}
		}
	}

	finding.Count = len(issues)
	switch {
	case len(issues) > 0:
		finding.Details = map[string]interface{}{
			"issues":         issues,
			"recommendation": "Set all critical audit categories to 'Success, Failure' (Advanced Audit Policy or the Default Domain Controllers GPO's legacy Audit Policy).",
		}
	case measured == 0:
		finding.Details = notConfiguredViaGPO()
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDCAuditPolicyIncompleteDetector())
}
