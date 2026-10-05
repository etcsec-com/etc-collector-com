package nist

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/auditpolicy"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AU2AuditEventsDetector checks NIST AU-2 audit events compliance
type AU2AuditEventsDetector struct {
	audit.BaseDetector
}

// NewAU2AuditEventsDetector creates a new detector
func NewAU2AuditEventsDetector() *AU2AuditEventsDetector {
	return &AU2AuditEventsDetector{
		BaseDetector: audit.NewBaseDetector("NIST_AU_2_AUDIT_EVENTS", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *AU2AuditEventsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Framing fix, verified against NIST SP 800-53 Rev 5 (nvlpubs.
	// nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf, Chapter 3,
	// p. 66). AU-2 requires an organization to identify loggable event types
	// and select a subset for logging based on its own risk assessment
	// ("[Assignment: organization-defined event types...]") - it does not
	// mandate that these 9 specific Windows audit categories be set to any
	// particular level. The categories and per-category minimums below are
	// ETC-chosen defaults implementing that organization-defined selection,
	// not values NIST itself specifies - Description reworded accordingly.
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "NIST AU-2 Audit Events Non-Compliant",
		Description: "Audit event configuration does not meet ETC's organization-defined event-type selection implementing NIST SP 800-53 AU-2. AU-2 itself leaves the specific event types and levels organization-defined based on risk assessment - the 9 categories and minimums checked here are ETC-chosen defaults, not values mandated by the standard.",
		Count:       0,
		Details: map[string]interface{}{
			"framework":   "NIST",
			"control":     "AU-2",
			"publication": "SP 800-53",
		},
	}

	// "Directory Service Access" is, unusually, both a NIST AU-2
	// category name and the name of one specific Advanced Audit Policy
	// subcategory - so it prefers that subcategory's audit.csv value when a
	// GPO configures it (the authoritative source auditpol itself reports
	// under the same name), matching DC01's actual state where that's
	// exactly what's configured. The other 8 categories have no single
	// matching subcategory and stay on the legacy [Event Audit] rollup.
	// An earlier version substituted an all-zero EventAudit whenever [Event Audit]
	// was absent everywhere, on the assumption that meant "nothing
	// audited" - disproved on DC01, which audits actively but entirely
	// outside of Group Policy
	// (docs/security-validation/results/t128-croise/METHODE-ET-VERDICTS.md).
	// Absence of GPO evidence is no longer treated as evidence of a
	// violation: a check with neither source is skipped, not maximized.
	ea := helpers.GetEventAudit(data.GPOPolicies)
	adv := auditpolicy.GetAdvancedAudit(data.GPOPolicies)

	type check struct {
		name   string
		guid   string // "" if this category has no single matching subcategory
		legacy func(*audit.EventAudit) int
		min    int
	}
	checks := []check{
		{"Account Logon", "", func(e *audit.EventAudit) int { return e.AuditAccountLogon }, 3},
		{"Account Management", "", func(e *audit.EventAudit) int { return e.AuditAccountManage }, 3},
		{"Directory Service Access", auditpolicy.DirectoryServiceAccess, func(e *audit.EventAudit) int { return e.AuditDSAccess }, 1},
		{"Logon/Logoff", "", func(e *audit.EventAudit) int { return e.AuditLogonEvents }, 3},
		{"Object Access", "", func(e *audit.EventAudit) int { return e.AuditObjectAccess }, 1},
		{"Policy Change", "", func(e *audit.EventAudit) int { return e.AuditPolicyChange }, 3},
		{"Privilege Use", "", func(e *audit.EventAudit) int { return e.AuditPrivilegeUse }, 2},
		{"Process Tracking", "", func(e *audit.EventAudit) int { return e.AuditProcessTracking }, 1},
		{"System Events", "", func(e *audit.EventAudit) int { return e.AuditSystemEvents }, 3},
	}

	var failures []string
	for _, c := range checks {
		v, ok := auditpolicy.Level(adv, c.guid, ea, c.legacy)
		if !ok {
			continue
		}
		if v < c.min {
			failures = append(failures, c.name)
		}
	}

	if len(failures) > 0 {
		finding.Count = len(failures)
		finding.Details["failingCategories"] = failures
		finding.Details["totalRequired"] = len(checks)
		finding.Details["recommendation"] = "Enable all required NIST AU-2 audit event categories via Group Policy: legacy Audit Policy for most categories, or Advanced Audit Policy Configuration (audit.csv) for Directory Service Access specifically."
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAU2AuditEventsDetector())
}
