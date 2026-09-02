package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestR4Logging_NoEventAuditAnywhere_NoViolation covers T_132/D3: DC01
// disproved the T_118 assumption that a domain with no [Event Audit]
// section anywhere audits nothing — it audits actively, entirely outside of
// Group Policy. Absence of GPO evidence must not be reported as a maximal
// violation.
func TestR4Logging_NoEventAuditAnywhere_NoViolation(t *testing.T) {
	d := NewR4LoggingDetector()
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{some-gpo}": {}, // no EventAudit at all
	}}

	findings := d.Detect(context.Background(), data)

	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want a single finding with Count=0", findings)
	}
}

// TestR4Logging_ExplicitWeakEventAudit_StillFlagged is the regression check
// for T_118's real fix: when a GPO DOES have an [Event Audit] section
// showing weak values, that must still be flagged — this behavior predates
// T_132 and must not change.
func TestR4Logging_ExplicitWeakEventAudit_StillFlagged(t *testing.T) {
	d := NewR4LoggingDetector()
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{some-gpo}": {EventAudit: &audit.EventAudit{}}, // present but all-zero
	}}

	findings := d.Detect(context.Background(), data)

	if len(findings) != 1 || findings[0].Count != 5 {
		t.Fatalf("got %+v, want a single finding with Count=5 (all 5 R4 categories violated)", findings)
	}
}

// TestR4Logging_CompliantEventAudit_NoViolation confirms the threshold logic
// itself (unchanged by T_132) still recognizes a fully compliant policy.
func TestR4Logging_CompliantEventAudit_NoViolation(t *testing.T) {
	d := NewR4LoggingDetector()
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{some-gpo}": {EventAudit: &audit.EventAudit{
			AuditAccountLogon:  3,
			AuditAccountManage: 3,
			AuditLogonEvents:   3,
			AuditPolicyChange:  3,
			AuditPrivilegeUse:  2,
		}},
	}}

	findings := d.Detect(context.Background(), data)

	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0", findings)
	}
}
