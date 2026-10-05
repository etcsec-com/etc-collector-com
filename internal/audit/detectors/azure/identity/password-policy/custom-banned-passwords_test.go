package passwordpolicy

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestBannedPasswordsDetector_FiresWhenNoCustomList reproduces the audit
// finding: today the detector sets Count=1 for ANY collected tenant config,
// regardless of whether a custom banned password list is actually
// configured.
func TestBannedPasswordsDetector_FiresWhenNoCustomList(t *testing.T) {
	d := NewCustomBannedPasswordsDetector()

	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{
			CustomBannedPasswordListConfigured: false,
		},
	}
	if got := d.Detect(context.Background(), data)[0].Count; got != 1 {
		t.Fatalf("expected Count=1 when no custom list is configured, got %d", got)
	}
}

// TestBannedPasswordsDetector_SilentWhenCustomListConfigured is the case
// that proves the fix: a tenant with a non-empty custom banned password
// list must NOT be flagged. On unpatched code this fails (Count=1 always).
func TestBannedPasswordsDetector_SilentWhenCustomListConfigured(t *testing.T) {
	d := NewCustomBannedPasswordsDetector()

	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{
			CustomBannedPasswordListConfigured: true,
		},
	}
	if got := d.Detect(context.Background(), data)[0].Count; got != 0 {
		t.Fatalf("expected Count=0 when custom list is configured, got %d", got)
	}
}
