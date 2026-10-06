package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/auditpolicy"
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

	// Account Logon (credential validation at the DC) and Logon/Logoff
	// (interactive/network logon) are two distinct legacy categories, each
	// resolved against its own Advanced Audit Policy subcategory.
	accountLogon, accountLogonOK := advancedAuditLevel(data, auditpolicy.CredentialValidation, func(e *audit.EventAudit) int {
		return e.AuditAccountLogon
	})
	logonEvents, logonEventsOK := advancedAuditLevel(data, auditpolicy.Logon, func(e *audit.EventAudit) int {
		return e.AuditLogonEvents
	})

	if !accountLogonOK && !logonEventsOK {
		finding.Details = notConfiguredViaGPO()
		return []types.Finding{finding}
	}

	// 3 = Success+Failure (both required). A category with no evidence from
	// either source is not counted as missing - see advancedAuditLevel.
	var missing []string
	details := map[string]interface{}{}
	if accountLogonOK {
		details["auditAccountLogon"] = accountLogon
		if accountLogon < 3 {
			missing = append(missing, "AuditAccountLogon")
		}
	}
	if logonEventsOK {
		details["auditLogonEvents"] = logonEvents
		if logonEvents < 3 {
			missing = append(missing, "AuditLogonEvents")
		}
	}

	if len(missing) > 0 {
		finding.Count = len(missing)
		details["missingCategories"] = missing
		details["requiredValue"] = 3
		details["requiredValueMeaning"] = "Success and Failure"
		details["recommendation"] = "Enable 'Audit Account Logon Events' and 'Audit Logon Events' (or their Advanced Audit Policy subcategories) for both Success and Failure."
		finding.Details = details
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAuditLogonEventsDetector())
}
