package disa

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/auditpolicy"
)

func compliantAuditCSV() map[string]int {
	return map[string]int{
		auditpolicy.CredentialValidation:    3,
		auditpolicy.SecurityGroupManagement: 3,
		auditpolicy.ProcessCreation:         1,
		auditpolicy.Logon:                   3,
		auditpolicy.AuditPolicyChange:       3,
		auditpolicy.SensitivePrivilegeUse:   2,
		auditpolicy.SecurityStateChange:     1,
	}
}

// TestDISAAuditPolicies_NoEvidenceAnywhere_NoViolation is the T_132/D3
// regression test for the three false findings security identified against
// DC01 (V-63455, V-63465, plus NIST's Directory Service Access) — DC01 has
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
// the count drop back to 0 — mirrored live against DC01 in
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
	if len(failing) != 1 || failing[0] != "V-63455: Logon/Logoff (Logon)" {
		t.Fatalf("failingSTIGs = %v, want exactly [\"V-63455: Logon/Logoff (Logon)\"]", failing)
	}
}

// TestDISAAuditPolicies_LegacyEventAuditWeak_StillFlagged is the regression
// check that a domain configuring the legacy [Event Audit] section (rather
// than Advanced Audit Policy) is still evaluated as before T_132.
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
