package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/auditpolicy"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AuditPrivilegeUseDetector checks if privilege use is audited
type AuditPrivilegeUseDetector struct {
	audit.BaseDetector
}

// NewAuditPrivilegeUseDetector creates a new detector
func NewAuditPrivilegeUseDetector() *AuditPrivilegeUseDetector {
	return &AuditPrivilegeUseDetector{
		BaseDetector: audit.NewBaseDetector("AUDIT_PRIVILEGE_USE_DISABLED", audit.CategoryMonitoring),
	}
}

// Detect executes the detection
func (d *AuditPrivilegeUseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Privilege Use Auditing Disabled",
		Description: "Privilege use events are not audited, preventing detection of privilege abuse and token manipulation.",
		Count:       0,
	}

	value, ok := advancedAuditLevel(data, auditpolicy.SensitivePrivilegeUse, func(e *audit.EventAudit) int {
		return e.AuditPrivilegeUse
	})
	if !ok {
		finding.Details = notConfiguredViaGPO()
		return []types.Finding{finding}
	}

	// At minimum, Failure should be audited (value >= 2)
	if value < 2 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"currentValue":    value,
			"requiredMinimum": 2,
			"recommendation":  "Enable 'Audit Sensitive Privilege Use' (Advanced Audit Policy) or 'Audit Privilege Use' (legacy) for at least Failure events.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAuditPrivilegeUseDetector())
}
