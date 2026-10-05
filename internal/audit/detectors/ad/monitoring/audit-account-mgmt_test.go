package monitoring

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/auditpolicy"
)

func TestAuditAccountMgmt_AdvancedAuditPolicyPrecedence(t *testing.T) {
	d := NewAuditAccountMgmtDetector()

	t.Run("legacy Event Audit shows nothing audited but audit.csv configures the subcategory: not flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{
				"GUID": {
					EventAudit:    &audit.EventAudit{AuditAccountManage: 0},
					AdvancedAudit: map[string]int{auditpolicy.UserAccountManagement: 3},
				},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("expected count=0 (subcategory wins), got %d", findings[0].Count)
		}
	})

	t.Run("legacy Event Audit shows fully audited but audit.csv configures the subcategory as insufficient: flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{
				"GUID": {
					EventAudit:    &audit.EventAudit{AuditAccountManage: 3},
					AdvancedAudit: map[string]int{auditpolicy.UserAccountManagement: 0},
				},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("expected count=1 (subcategory wins over legacy), got %d", findings[0].Count)
		}
	})

	t.Run("neither source configures it: not flagged, and the finding says so honestly", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{
				"GUID": {},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("expected count=0 (no evidence is not proof of a violation), got %d", findings[0].Count)
		}
		if findings[0].Details == nil {
			t.Fatal("expected details explaining the finding is inconclusive, got nil")
		}
	})

	t.Run("no audit.csv anywhere: falls back to the legacy value", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{
				"GUID": {
					EventAudit: &audit.EventAudit{AuditAccountManage: 1},
				},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("expected count=1 (legacy fallback, value=1<3), got %d", findings[0].Count)
		}
	})
}
