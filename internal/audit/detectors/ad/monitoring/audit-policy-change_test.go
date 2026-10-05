package monitoring

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance/auditpolicy"
)

func TestAuditPolicyChange_AdvancedAuditPolicyPrecedence(t *testing.T) {
	d := NewAuditPolicyChangeDetector()

	t.Run("legacy Event Audit shows nothing audited but audit.csv configures the subcategory: not flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{
				"GUID": {
					EventAudit:    &audit.EventAudit{AuditPolicyChange: 0},
					AdvancedAudit: map[string]int{auditpolicy.AuditPolicyChange: 3},
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
					EventAudit:    &audit.EventAudit{AuditPolicyChange: 3},
					AdvancedAudit: map[string]int{auditpolicy.AuditPolicyChange: 1},
				},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("expected count=1 (subcategory wins over legacy), got %d", findings[0].Count)
		}
	})

	t.Run("neither source configures it: not flagged, honest details", func(t *testing.T) {
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
}
