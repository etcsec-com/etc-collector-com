package industry

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestEncryptionAtRest_SeverityIsInfoNotMedium is a red->green test:
// before the fix, this fired SeverityMedium on every single audit
// unconditionally (no LDAP signal is ever read), overstating a standing
// "verify manually" reminder as a confirmed Medium-severity violation. It
// must be Info, matching the precedent already set by
// AUDIT_LOG_RETENTION_SHORT for the exact same "cannot verify via LDAP"
// shape of check.
func TestEncryptionAtRest_SeverityIsInfoNotMedium(t *testing.T) {
	d := NewEncryptionAtRestDetector()
	findings := d.Detect(context.Background(), &audit.DetectorData{})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityInfo {
		t.Errorf("Severity = %q, want %q (standing reminder, not a measured violation)", findings[0].Severity, types.SeverityInfo)
	}
}
