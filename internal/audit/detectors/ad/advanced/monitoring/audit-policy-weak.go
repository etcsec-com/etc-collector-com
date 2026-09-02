package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
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

// Detect executes the detection
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
	if ea == nil {
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
