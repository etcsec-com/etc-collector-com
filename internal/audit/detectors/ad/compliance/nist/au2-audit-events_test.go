package nist

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/auditpolicy"
)

// TestNIST_AU2_NoEvidenceAnywhere_NoViolation is the T_132/D3 regression
// test for the false "Directory Service Access" finding security identified
// against DC01: with no [Event Audit] section and no audit.csv in any
// applied GPO, none of the 9 checks has anything to compare against.
func TestNIST_AU2_NoEvidenceAnywhere_NoViolation(t *testing.T) {
	d := NewAU2AuditEventsDetector()
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{some-gpo}": {},
	}}

	findings := d.Detect(context.Background(), data)

	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0", findings)
	}
}

// TestNIST_AU2_DSAccessViaAdvancedAudit_Compliant confirms the "Directory
// Service Access" check reads audit.csv's own subcategory of the same name
// even with no legacy [Event Audit] section at all.
func TestNIST_AU2_DSAccessViaAdvancedAudit_Compliant(t *testing.T) {
	d := NewAU2AuditEventsDetector()
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{some-gpo}": {AdvancedAudit: map[string]int{auditpolicy.DirectoryServiceAccess: 3}},
	}}

	findings := d.Detect(context.Background(), data)

	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0 — DS Access is configured (Success and Failure) via audit.csv", findings)
	}
}

// TestNIST_AU2_DSAccessViaAdvancedAudit_Weak proves the check genuinely
// detects a real violation via Advanced Audit Policy Configuration when
// that subcategory is below threshold, with the other 8 categories
// correctly skipped (no legacy evidence for them in this fixture).
func TestNIST_AU2_DSAccessViaAdvancedAudit_Weak(t *testing.T) {
	d := NewAU2AuditEventsDetector()
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{some-gpo}": {AdvancedAudit: map[string]int{auditpolicy.DirectoryServiceAccess: 0}},
	}}

	findings := d.Detect(context.Background(), data)

	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1", findings)
	}
	failing, _ := findings[0].Details["failingCategories"].([]string)
	if len(failing) != 1 || failing[0] != "Directory Service Access" {
		t.Fatalf("failingCategories = %v, want exactly [\"Directory Service Access\"]", failing)
	}
}

// TestNIST_AU2_LegacyEventAuditWeak_StillFlagged is the regression check
// that a domain configuring the legacy [Event Audit] section is still
// evaluated across all 9 categories as before T_132.
func TestNIST_AU2_LegacyEventAuditWeak_StillFlagged(t *testing.T) {
	d := NewAU2AuditEventsDetector()
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{some-gpo}": {EventAudit: &audit.EventAudit{}}, // present but all-zero
	}}

	findings := d.Detect(context.Background(), data)

	if len(findings) != 1 || findings[0].Count != 9 {
		t.Fatalf("got %+v, want Count=9 (all 9 AU-2 categories violated)", findings)
	}
}
