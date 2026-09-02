package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
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

	ea := helpers.GetEventAudit(data.GPOPolicies)
	if ea == nil {
		return []types.Finding{finding}
	}

	// At minimum, Failure should be audited (value >= 2)
	if ea.AuditPrivilegeUse < 2 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"currentValue":    ea.AuditPrivilegeUse,
			"requiredMinimum": 2,
			"recommendation":  "Enable 'Audit Privilege Use' for at least Failure events.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAuditPrivilegeUseDetector())
}
