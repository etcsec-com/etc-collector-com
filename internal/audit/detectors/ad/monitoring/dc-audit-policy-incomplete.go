package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
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

	ea := helpers.GetEventAudit(data.GPOPolicies)
	if ea == nil {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"issue":          "No audit policy found in any GPO",
			"recommendation": "Configure audit policy via Default Domain Controllers Policy to log both success and failure for critical categories.",
		}
		return []types.Finding{finding}
	}

	// Check critical categories - value 3 means both success and failure
	issues := []string{}
	if ea.AuditAccountLogon != 3 {
		issues = append(issues, "Account Logon: not logging both success and failure")
	}
	if ea.AuditAccountManage != 3 {
		issues = append(issues, "Account Management: not logging both success and failure")
	}
	if ea.AuditLogonEvents != 3 {
		issues = append(issues, "Logon Events: not logging both success and failure")
	}
	if ea.AuditPolicyChange != 3 {
		issues = append(issues, "Policy Change: not logging both success and failure")
	}
	if ea.AuditSystemEvents != 3 {
		issues = append(issues, "System Events: not logging both success and failure")
	}
	if ea.AuditDSAccess < 2 { // At least failure auditing for DS Access
		issues = append(issues, "Directory Service Access: failure auditing not enabled")
	}

	finding.Count = len(issues)
	if len(issues) > 0 {
		finding.Details = map[string]interface{}{
			"issues":         issues,
			"recommendation": "Set all critical audit categories to 'Success, Failure' in the Default Domain Controllers GPO.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDCAuditPolicyIncompleteDetector())
}
