package disa

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/auditpolicy"
)

// SecurityGroupManagement dropped from 3 (Both) to 1 (Success only)
// and SensitivePrivilegeUse rose from 2 (Failure only) to 3 (Both) - the two
// thresholds that were actually wrong (WN22-AU-000100/V-254303 and
// WN22-AU-000300+000310/V-254323+V-254324 respectively).
func compliantAuditCSV() map[string]int {
	return map[string]int{
		auditpolicy.CredentialValidation:    3,
		auditpolicy.SecurityGroupManagement: 1,
		auditpolicy.ProcessCreation:         1,
		auditpolicy.Logon:                   3,
		auditpolicy.AuditPolicyChange:       3,
		auditpolicy.SensitivePrivilegeUse:   3,
		auditpolicy.SecurityStateChange:     1,
	}
}

// TestDISAAuditPolicies_NoEvidenceAnywhere_NoViolation is a
// regression test for the three false findings security identified against
// DC01 (V-63455, V-63465, plus NIST's Directory Service Access) - DC01 has
// neither an [Event Audit] section nor an audit.csv in any applied GPO, so
// none of the 7 checks has anything to compare against.
func TestDISAAuditPolicies_NoEvidenceAnywhere_NoViolation(t *testing.T) {
	d := NewAuditPoliciesDetector()
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{some-gpo}": {},
	}}

	findings := d.Detect(context.Background(), data)

	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0", findings)
	}
}

// TestDISAAuditPolicies_AdvancedAuditCompliant_NoViolation confirms a GPO
// that configures Advanced Audit Policy (audit.csv) compliantly is read
// correctly even with no legacy [Event Audit] section at all.
func TestDISAAuditPolicies_AdvancedAuditCompliant_NoViolation(t *testing.T) {
	d := NewAuditPoliciesDetector()
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{some-gpo}": {AdvancedAudit: compliantAuditCSV()},
	}}

	findings := d.Detect(context.Background(), data)

	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0", findings)
	}
}

// TestDISAAuditPolicies_OneSubcategoryWeak_OnlyThatOneFlagged proves the
// detector can genuinely detect a real violation via Advanced Audit Policy
// Configuration (not just stay silent), and that fixing just that one
// subcategory (the literal remediation this detector prints) is what makes
// the count drop back to 0 - mirrored live against DC01 in
// docs/security-validation/results/t132-manual/.
func TestDISAAuditPolicies_OneSubcategoryWeak_OnlyThatOneFlagged(t *testing.T) {
	adv := compliantAuditCSV()
	adv[auditpolicy.Logon] = 1 // Success only, not "Success and Failure"

	d := NewAuditPoliciesDetector()
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{some-gpo}": {AdvancedAudit: adv},
	}}

	findings := d.Detect(context.Background(), data)

	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1", findings)
	}
	failing, _ := findings[0].Details["failingSTIGs"].([]string)
	want := "WN22-AU-000190/000200 (V-254312/V-254313): Logon/Logoff (Logon)"
	if len(failing) != 1 || failing[0] != want {
		t.Fatalf("failingSTIGs = %v, want exactly [%q]", failing, want)
	}
}

// TestDISAAuditPolicies_SecurityGroupManagement_SuccessOnlyCompliant is a
// red->green test: before the fix, Security Group Management required
// value>=3 (Both), but the real WN22-AU-000100 (V-254303) requirement is
// Success only. A domain auditing Success-only for this subcategory must not
// be flagged.
func TestDISAAuditPolicies_SecurityGroupManagement_SuccessOnlyCompliant(t *testing.T) {
	adv := compliantAuditCSV()
	adv[auditpolicy.SecurityGroupManagement] = 1 // Success only

	d := NewAuditPoliciesDetector()
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{some-gpo}": {AdvancedAudit: adv},
	}}

	findings := d.Detect(context.Background(), data)

	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0 - Security Group Management only requires Success", findings)
	}
}

// TestDISAAuditPolicies_SensitivePrivilegeUse_FailureOnlyStillViolates is
// a red->green test: before the fix, Sensitive Privilege Use
// required only value>=2 (Failure), so a Failure-only domain (value=2)
// wrongly passed as compliant even though the real WN22-AU-000300+000310
// (V-254323+V-254324) requirement is Success AND Failure (value=3).
func TestDISAAuditPolicies_SensitivePrivilegeUse_FailureOnlyStillViolates(t *testing.T) {
	adv := compliantAuditCSV()
	adv[auditpolicy.SensitivePrivilegeUse] = 2 // Failure only

	d := NewAuditPoliciesDetector()
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{some-gpo}": {AdvancedAudit: adv},
	}}

	findings := d.Detect(context.Background(), data)

	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 - Sensitive Privilege Use requires Success AND Failure, Failure-only must still violate", findings)
	}
}

// TestDISAAuditPolicies_LegacyEventAuditWeak_StillFlagged is the regression
// check that a domain configuring the legacy [Event Audit] section (rather
// than Advanced Audit Policy) is still evaluated the same way.
func TestDISAAuditPolicies_LegacyEventAuditWeak_StillFlagged(t *testing.T) {
	d := NewAuditPoliciesDetector()
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{some-gpo}": {EventAudit: &audit.EventAudit{}}, // present but all-zero
	}}

	findings := d.Detect(context.Background(), data)

	if len(findings) != 1 || findings[0].Count != 7 {
		t.Fatalf("got %+v, want Count=7 (all 7 DISA checks violated)", findings)
	}
}
