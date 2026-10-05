package monitoring

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/auditpolicy"
)

func TestDCAuditPolicyIncomplete_AdvancedAuditPolicyPrecedence(t *testing.T) {
	d := NewDCAuditPolicyIncompleteDetector()

	t.Run("legacy Event Audit shows every category unaudited but audit.csv configures every subcategory correctly: not flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{
				"GUID": {
					EventAudit: &audit.EventAudit{}, // all zero = "nothing audited" at legacy level
					AdvancedAudit: map[string]int{
						auditpolicy.CredentialValidation:   3,
						auditpolicy.UserAccountManagement:  3,
						auditpolicy.Logon:                  3,
						auditpolicy.AuditPolicyChange:      3,
						auditpolicy.SecurityStateChange:    3,
						auditpolicy.DirectoryServiceAccess: 2,
					},
				},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("expected count=0 (subcategories win over legacy for every category), got %d: %v", findings[0].Count, findings[0].Details)
		}
	})

	t.Run("legacy shows fully audited but one subcategory is insufficient in audit.csv: that one category is flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{
				"GUID": {
					EventAudit: &audit.EventAudit{
						AuditAccountLogon:  3,
						AuditAccountManage: 3,
						AuditLogonEvents:   3,
						AuditPolicyChange:  3,
						AuditSystemEvents:  3,
						AuditDSAccess:      3,
					},
					AdvancedAudit: map[string]int{
						auditpolicy.AuditPolicyChange: 0,
					},
				},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("expected count=1 (only Policy Change subcategory is insufficient), got %d: %v", findings[0].Count, findings[0].Details)
		}
	})

	t.Run("no audit policy anywhere: not flagged as incomplete, finding is honest instead of categorical", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{"GUID": {}},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("expected count=0 (no GPO evidence is not proof of an incomplete policy), got %d", findings[0].Count)
		}
		if findings[0].Details == nil {
			t.Fatal("expected honest details explaining nothing is configured via GPO, got nil")
		}
	})
}
