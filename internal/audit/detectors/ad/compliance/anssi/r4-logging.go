package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R4LoggingDetector checks ANSSI R4 logging compliance
type R4LoggingDetector struct {
	audit.BaseDetector
}

// NewR4LoggingDetector creates a new detector
func NewR4LoggingDetector() *R4LoggingDetector {
	return &R4LoggingDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R4_LOGGING", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *R4LoggingDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "ANSSI R4 - Insufficient Logging Configuration",
		Description: "Logging configuration does not meet ANSSI R4 requirements. Critical audit categories must be enabled for Success and Failure.",
		Count:       0,
		Details: map[string]interface{}{
			"framework": "ANSSI",
			"control":   "R4",
		},
	}

	// T_132/D3: T_118 had substituted an all-zero EventAudit whenever
	// [Event Audit] was absent from every GPO, on the assumption that meant
	// "nothing audited" — every `< min` comparison below then fails,
	// producing the maximal violation count. Disproved on DC01, which
	// audits actively (auditpol showed 17 active subcategories) entirely
	// outside of Group Policy — no GPO has to configure auditing for a
	// domain to actually audit
	// (docs/security-validation/results/t128-croise/METHODE-ET-VERDICTS.md).
	// None of R4's 5 checks map to one specific Advanced Audit Policy
	// subcategory (unlike DISA_AUDIT_POLICIES/NIST_AU_2_AUDIT_EVENTS, see
	// compliance/auditpolicy), so there's no finer-grained source to fall
	// back to here: absent [Event Audit] everywhere, this detector has
	// nothing to check against and reports no violation rather than guess
	// the worst case.
	ea := helpers.GetEventAudit(data.GPOPolicies)
	if ea == nil {
		return []types.Finding{finding}
	}

	// ANSSI R4 requires: Account Logon, Account Management, Logon/Logoff, Policy Change, Privilege Use
	var violations []string
	if ea.AuditAccountLogon < 3 {
		violations = append(violations, "Account Logon events not fully audited")
	}
	if ea.AuditAccountManage < 3 {
		violations = append(violations, "Account Management events not fully audited")
	}
	if ea.AuditLogonEvents < 3 {
		violations = append(violations, "Logon/Logoff events not fully audited")
	}
	if ea.AuditPolicyChange < 3 {
		violations = append(violations, "Policy Change events not fully audited")
	}
	if ea.AuditPrivilegeUse < 2 {
		violations = append(violations, "Privilege Use events not audited for Failure")
	}

	if len(violations) > 0 {
		finding.Count = len(violations)
		finding.Details["violations"] = violations
		finding.Details["recommendation"] = "Enable all required audit categories for Success and Failure as per ANSSI recommendations."
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewR4LoggingDetector())
}
