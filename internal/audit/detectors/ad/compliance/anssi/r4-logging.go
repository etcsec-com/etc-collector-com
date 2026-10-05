package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R4LoggingDetector checks ANSSI PA-099 R13 security event logging compliance.
// Name/ID kept as "R4" for backward compatibility (frozen by
// internal/audit/compliance/mappings.go); see the anssiR13LoggingControl
// comment below for why R13 is the correct control.
type R4LoggingDetector struct {
	audit.BaseDetector
}

// NewR4LoggingDetector creates a new detector
func NewR4LoggingDetector() *R4LoggingDetector {
	return &R4LoggingDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R4_LOGGING", audit.CategoryCompliance),
	}
}

// This detector's ID (frozen - see internal/audit/compliance/mappings.go,
// out of scope here) says "R4", but R4 in ANSSI-PA-099 is
// "Mettre en œuvre un processus itératif d'amélioration continue du
// cloisonnement du SI" - unrelated to logging. mappings.go itself already
// tags ANSSI_R4_LOGGING with the CORRECT control, PA-099 R13 ("Journaliser
// et centraliser les évènements de sécurité", p.30): this file's own
// title/description just never matched that mapping. R13's text explicitly
// defers the specific event categories to two other ANSSI guides ("La
// journalisation n'est pas un sujet traité dans ce document") - it does not
// itemize Account Logon/Management/Logon-Logoff/Policy-Change/Privilege-Use
// by name, so the 5 categories checked below are this product's own
// reasonable operationalization of "évènements de sécurité importants",
// not a verbatim R13 requirement. Source confirms the check is a legitimate
// implementation of the general R13 obligation; nothing below the citation
// fix changes.
const anssiR13LoggingControl = "R13"

// Detect executes the detection
func (d *R4LoggingDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "ANSSI PA-099 R13 - Insufficient Security Event Logging",
		Description: "Logging configuration does not meet ANSSI PA-099 R13 (\"Journaliser et centraliser les évènements de sécurité\", p.30). R13 itself defers the exact event categories to two companion ANSSI logging guides; the categories checked here (Account Logon, Account Management, Logon/Logoff, Policy Change, Privilege Use) are this product's operationalization of R13's general requirement, not a verbatim R13 list.",
		Count:       0,
		Details: map[string]interface{}{
			"framework": "ANSSI-PA-099",
			"control":   anssiR13LoggingControl,
		},
	}

	// An earlier version substituted an all-zero EventAudit whenever
	// [Event Audit] was absent from every GPO, on the assumption that meant
	// "nothing audited" - every `< min` comparison below then fails,
	// producing the maximal violation count. Disproved on DC01, which
	// audits actively (auditpol showed 17 active subcategories) entirely
	// outside of Group Policy - no GPO has to configure auditing for a
	// domain to actually audit
	// (docs/security-validation/results/t128-croise/METHODE-ET-VERDICTS.md).
	// None of these 5 checks map to one specific Advanced Audit Policy
	// subcategory (unlike DISA_AUDIT_POLICIES/NIST_AU_2_AUDIT_EVENTS, see
	// compliance/auditpolicy), so there's no finer-grained source to fall
	// back to here: absent [Event Audit] everywhere, this detector has
	// nothing to check against and reports no violation rather than guess
	// the worst case.
	ea := helpers.GetEventAudit(data.GPOPolicies)
	if ea == nil {
		return []types.Finding{finding}
	}

	// ANSSI PA-099 R13 (operationalized): Account Logon, Account Management, Logon/Logoff, Policy Change, Privilege Use
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
