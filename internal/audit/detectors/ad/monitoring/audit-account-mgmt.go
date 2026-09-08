package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/auditpolicy"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AuditAccountMgmtDetector checks if account management events are audited
type AuditAccountMgmtDetector struct {
	audit.BaseDetector
}

// NewAuditAccountMgmtDetector creates a new detector
func NewAuditAccountMgmtDetector() *AuditAccountMgmtDetector {
	return &AuditAccountMgmtDetector{
		BaseDetector: audit.NewBaseDetector("AUDIT_ACCOUNT_MGMT_DISABLED", audit.CategoryMonitoring),
	}
}

// Detect executes the detection
func (d *AuditAccountMgmtDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Account Management Auditing Disabled",
		Description: "Account management events are not audited for Success and Failure, preventing detection of unauthorized account changes.",
		Count:       0,
	}

	value, ok := advancedAuditLevel(data, auditpolicy.UserAccountManagement, func(e *audit.EventAudit) int {
		return e.AuditAccountManage
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
			"recommendation": "Enable 'Audit User Account Management' (Advanced Audit Policy) or 'Audit Account Management' (legacy Audit Policy) for both Success and Failure.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAuditAccountMgmtDetector())
}
