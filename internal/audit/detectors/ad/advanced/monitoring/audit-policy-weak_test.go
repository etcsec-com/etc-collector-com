package monitoring

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// AUDIT_POLICY_WEAK only ever read the legacy [Event Audit] rollup.
// When no GPO has an [Event Audit] section, the old code returned Count=0
// unconditionally - silently calling both "nothing configured anywhere" and
// "audited correctly via Advanced Audit Policy only" compliant, without
// telling them apart.
func TestAuditPolicyWeak_NoLegacySection(t *testing.T) {
	t.Run("no legacy AND no advanced audit anywhere: worst case, must flag all categories", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{
				"GUID": {}, // no EventAudit, no AdvancedAudit
			},
		}
		findings := NewAuditPolicyWeakDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		f := findings[0]
		if f.Count != len(legacyCategoryNames) {
			t.Fatalf("Count = %d, want %d (all legacy categories, since nothing is configured anywhere)", f.Count, len(legacyCategoryNames))
		}
		if f.Severity != "critical" {
			t.Fatalf("Severity = %q, want \"critical\" for total absence of audit configuration", f.Severity)
		}
	})

	t.Run("no legacy but Advanced Audit Policy IS deployed: must not silently claim compliance", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{
				"GUID": {
					AdvancedAudit: map[string]int{
						"{0cce9215-69ae-11d9-bed3-505054503030}": 3, // Logon subcategory, Success+Failure
					},
				},
			},
		}
		findings := NewAuditPolicyWeakDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		f := findings[0]
		if f.Count != 0 {
			t.Fatalf("Count = %d, want 0 (this detector cannot claim a violation it did not check)", f.Count)
		}
		if f.Details == nil || f.Details["note"] == nil {
			t.Fatalf("Details = %v, want a transparency note explaining Advanced Audit Policy wasn't evaluated - a bare empty finding silently implies verified compliance", f.Details)
		}
	})
}
