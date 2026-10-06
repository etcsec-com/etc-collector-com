package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// A domain managing its audit policy exclusively through the modern
// Advanced Audit Policy Configuration (audit.csv, GPOPolicy.AdvancedAudit)
// has an empty legacy [Event Audit] section by design. The previous
// implementation only checked [Event Audit] and would have flagged this as
// non-compliant. This test would have FAILED against the old
// implementation and passes against the fix.
func TestR38AdvancedAudit_AdvancedAuditCSVOnly_NotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{aaaaaaaa-1111-2222-3333-444444444444}": {
				GUID:          "{aaaaaaaa-1111-2222-3333-444444444444}",
				EventAudit:    nil, // legacy section unset - managed via audit.csv instead
				AdvancedAudit: map[string]int{"{0cce9215-69ae-11d9-bed3-505054503030}": 3},
			},
		},
	}
	d := NewR38AdvancedAuditDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected a domain managed via audit.csv to be recognized as compliant, got %+v", findings)
	}
}

// The previous implementation accepted level 1 (success-only) on all five
// legacy categories as "enabled", silencing the check without any
// failure-event coverage. This test would have FAILED against the old
// implementation (level 1 on all five => compliant) and passes against the
// fix (level 3 required).
func TestR38AdvancedAudit_LegacyLevel1Only_StillFlagged(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{aaaaaaaa-1111-2222-3333-444444444444}": {
				GUID: "{aaaaaaaa-1111-2222-3333-444444444444}",
				EventAudit: &audit.EventAudit{
					AuditAccountLogon:  1,
					AuditAccountManage: 1,
					AuditDSAccess:      1,
					AuditLogonEvents:   1,
					AuditObjectAccess:  1,
				},
			},
		},
	}
	d := NewR38AdvancedAuditDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected success-only (level 1) legacy audit to still be flagged, got %+v", findings)
	}
}

func TestR38AdvancedAudit_LegacyLevel3All_NotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{aaaaaaaa-1111-2222-3333-444444444444}": {
				GUID: "{aaaaaaaa-1111-2222-3333-444444444444}",
				EventAudit: &audit.EventAudit{
					AuditAccountLogon:  3,
					AuditAccountManage: 3,
					AuditDSAccess:      3,
					AuditLogonEvents:   3,
					AuditObjectAccess:  3,
				},
			},
		},
	}
	d := NewR38AdvancedAuditDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected full success+failure legacy audit to be compliant, got %+v", findings)
	}
}
