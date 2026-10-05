package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestR4Logging_NoEventAuditAnywhere_NoViolation covers the fact that DC01
// disproved the prior assumption that a domain with no [Event Audit]
// section anywhere audits nothing - it audits actively, entirely outside of
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
// for the real fix above: when a GPO DOES have an [Event Audit] section
// showing weak values, that must still be flagged - this behavior predates
// that fix and must not change.
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

// TestR4Logging_CitesRealControl: the detector's ID is frozen
// as "R4" (external mappings.go dependency), but R4 in ANSSI-PA-099 is about
// Tier segmentation, not logging - mappings.go itself already tags this
// detector's real control as PA-099 R13. Before the fix, Details["control"]
// said "R4" (a control that doesn't cover logging at all); it must say "R13".
func TestR4Logging_CitesRealControl(t *testing.T) {
	d := NewR4LoggingDetector()
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{some-gpo}": {EventAudit: &audit.EventAudit{}},
	}}

	findings := d.Detect(context.Background(), data)

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if got := findings[0].Details["control"]; got != "R13" {
		t.Errorf("Details[control] = %v, want R13 (ANSSI-PA-099 R4 is Tier-segmentation, not logging)", got)
	}
	if got := findings[0].Details["framework"]; got != "ANSSI-PA-099" {
		t.Errorf("Details[framework] = %v, want ANSSI-PA-099", got)
	}
}

// TestR4Logging_CompliantEventAudit_NoViolation confirms the threshold logic
// itself (unchanged by the fix above) still recognizes a fully compliant policy.
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
