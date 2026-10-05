package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/auditpolicy"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AuditPolicyChangeDetector checks if policy change events are audited
type AuditPolicyChangeDetector struct {
	audit.BaseDetector
}

// NewAuditPolicyChangeDetector creates a new detector
func NewAuditPolicyChangeDetector() *AuditPolicyChangeDetector {
	return &AuditPolicyChangeDetector{
		BaseDetector: audit.NewBaseDetector("AUDIT_POLICY_CHANGE_DISABLED", audit.CategoryMonitoring),
	}
}

// Detect executes the detection
func (d *AuditPolicyChangeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Policy Change Auditing Disabled",
		Description: "Policy change events are not audited, preventing detection of GPO poisoning and security policy tampering.",
		Count:       0,
	}

	value, ok := advancedAuditLevel(data, auditpolicy.AuditPolicyChange, func(e *audit.EventAudit) int {
		return e.AuditPolicyChange
	})
	if !ok {
		finding.Details = notConfiguredViaGPO()
		return []types.Finding{finding}
	}

	if value < 3 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"currentValue":   value,
			"requiredValue":  3,
			"recommendation": "Enable 'Audit Policy Change' (Advanced Audit Policy or legacy Audit Policy) for both Success and Failure.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAuditPolicyChangeDetector())
}
