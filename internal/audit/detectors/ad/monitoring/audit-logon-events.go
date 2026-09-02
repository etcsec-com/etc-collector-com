package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AuditLogonEventsDetector checks if logon events are audited
type AuditLogonEventsDetector struct {
	audit.BaseDetector
}

// NewAuditLogonEventsDetector creates a new detector
func NewAuditLogonEventsDetector() *AuditLogonEventsDetector {
	return &AuditLogonEventsDetector{
		BaseDetector: audit.NewBaseDetector("AUDIT_LOGON_EVENTS_DISABLED", audit.CategoryMonitoring),
	}
}

// Detect executes the detection
func (d *AuditLogonEventsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Logon Event Auditing Insufficient",
		Description: "Logon events are not fully audited. Both Account Logon and Logon/Logoff events should audit Success and Failure.",
		Count:       0,
	}

	ea := helpers.GetEventAudit(data.GPOPolicies)
	if ea == nil {
		return []types.Finding{finding}
	}

	// Check both AuditAccountLogon and AuditLogonEvents
	// 3 = Success+Failure (both required)
	var missing []string
	if ea.AuditAccountLogon < 3 {
		missing = append(missing, "AuditAccountLogon")
	}
	if ea.AuditLogonEvents < 3 {
		missing = append(missing, "AuditLogonEvents")
	}

	if len(missing) > 0 {
		finding.Count = len(missing)
		finding.Details = map[string]interface{}{
			"missingCategories":    missing,
			"auditAccountLogon":    ea.AuditAccountLogon,
			"auditLogonEvents":     ea.AuditLogonEvents,
			"requiredValue":        3,
			"requiredValueMeaning": "Success and Failure",
			"recommendation":       "Enable 'Audit Account Logon Events' and 'Audit Logon Events' for both Success and Failure.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAuditLogonEventsDetector())
}
