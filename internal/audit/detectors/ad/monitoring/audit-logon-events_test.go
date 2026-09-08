package monitoring

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/auditpolicy"
)

func TestAuditLogonEvents_AdvancedAuditPolicyPrecedence(t *testing.T) {
	d := NewAuditLogonEventsDetector()

	t.Run("legacy shows both categories unaudited but audit.csv configures both subcategories: not flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{
				"GUID": {
					EventAudit: &audit.EventAudit{AuditAccountLogon: 0, AuditLogonEvents: 0},
					AdvancedAudit: map[string]int{
						auditpolicy.CredentialValidation: 3,
						auditpolicy.Logon:                3,
					},
				},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("expected count=0 (subcategories win), got %d", findings[0].Count)
		}
	})

	t.Run("legacy shows both categories fully audited but audit.csv configures Logon subcategory as insufficient: flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{
				"GUID": {
					EventAudit: &audit.EventAudit{AuditAccountLogon: 3, AuditLogonEvents: 3},
					AdvancedAudit: map[string]int{
						auditpolicy.Logon: 1,
					},
				},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("expected count=1 (Logon subcategory wins over legacy), got %d", findings[0].Count)
		}
	})

	t.Run("neither source configures either category: not flagged, honest details", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{"GUID": {}},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("expected count=0, got %d", findings[0].Count)
		}
		if findings[0].Details == nil {
			t.Fatal("expected honest details, got nil")
		}
	})

	t.Run("only one category has evidence: the unmeasured category is excluded, not counted as missing", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{
				"GUID": {
					AdvancedAudit: map[string]int{auditpolicy.Logon: 0},
				},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("expected count=1 (only Logon measured and insufficient), got %d", findings[0].Count)
		}
	})
}
