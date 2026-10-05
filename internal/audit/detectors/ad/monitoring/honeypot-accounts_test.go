package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestHoneypotAccounts_RealServiceAccountsAreNotDecoys locks in the fix for
// the false positive where real, unused-but-legitimate service accounts
// (svc_sql, svc_backup, backup_admin) were counted as honeypots merely for
// having an "attractive" name and no recorded logon.
func TestHoneypotAccounts_RealServiceAccountsAreNotDecoys(t *testing.T) {
	d := NewHoneypotAccountsDetector()

	t.Run("real dormant service accounts with generic names: not treated as honeypots", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{SAMAccountName: "svc_sql"},
				{SAMAccountName: "svc_backup"},
				{SAMAccountName: "backup_admin"},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("expected count=1 (no honeypots present), got %d: %v", findings[0].Count, findings[0].Details)
		}
	})

	t.Run("account with a deliberate decoy marker, never used: recognised as a honeypot", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{SAMAccountName: "svc_canary01"},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("expected count=0 (a genuine decoy is present), got %d", findings[0].Count)
		}
	})

	t.Run("account with a decoy marker but that has actually been used: not counted as an active decoy", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{SAMAccountName: "decoy-admin", LastLogon: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("expected count=1 (a used account isn't functioning as a decoy), got %d", findings[0].Count)
		}
	})

	t.Run("account with a decoy marker but disabled: not counted as an active decoy", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{SAMAccountName: "decoy-admin", Disabled: true},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("expected count=1 (a disabled account can't be monitored as a decoy), got %d", findings[0].Count)
		}
	})
}
