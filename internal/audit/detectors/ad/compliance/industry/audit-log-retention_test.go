package industry

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAuditLogRetention_SeverityIsInfo: this detector never
// reads any signal from data - Count is hardcoded to 1 and it fires on every
// audit regardless of domain state. It previously carried SeverityMedium,
// misrepresenting a standing "please verify manually" reminder as an actual
// detected finding. It must now match DATA_CLASSIFICATION_MISSING's honest
// SeverityInfo for the same class of "cannot verify via LDAP" reminder.
func TestAuditLogRetention_SeverityIsInfo(t *testing.T) {
	d := NewAuditLogRetentionDetector()
	findings := d.Detect(context.Background(), &audit.DetectorData{})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != types.SeverityInfo {
		t.Errorf("Severity = %v, want SeverityInfo (this check never detects an actual violation)", findings[0].Severity)
	}
}
