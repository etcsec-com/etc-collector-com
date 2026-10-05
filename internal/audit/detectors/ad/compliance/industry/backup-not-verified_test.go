package industry

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestBackupNotVerified_NeverEmits documents the RETIRER decision:
// backup verification status (job ran, restore tested) is an operational
// fact external to the directory - no LDAP attribute carries it, so the
// detector must not fabricate a finding for data it cannot measure. Before
// the fix, Detect() unconditionally returned one Finding{Count:0} as a
// "reminder"; after, it returns nothing, and it is no longer registered
// into audit.DefaultRegistry at all.
func TestBackupNotVerified_NeverEmits(t *testing.T) {
	d := NewBackupNotVerifiedDetector()
	got := d.Detect(context.Background(), &audit.DetectorData{})
	if len(got) != 0 {
		t.Fatalf("Detect() = %d findings, want 0 (backup verification is not measurable via LDAP; detector must not guess)", len(got))
	}
}

// TestBackupNotVerified_NotRegistered pins that RETIRER actually deregisters
// the detector - a client running a real audit must never see this ID.
func TestBackupNotVerified_NotRegistered(t *testing.T) {
	if _, ok := audit.DefaultRegistry.Get("BACKUP_AD_NOT_VERIFIED"); ok {
		t.Fatalf("BACKUP_AD_NOT_VERIFIED must not be registered (RETIRER)")
	}
}
