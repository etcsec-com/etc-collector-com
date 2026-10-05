package passwordpolicy

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Pre-fix bug: Detect set Count=1 as soon as AzureTenantConfig was non-nil,
// with no read of any password-protection field - it fired on every tenant
// where Azure collection succeeded at all, regardless of the real setting.
func TestPasswordProtectionDisabled_NoFalsePositiveWhenUnmeasured(t *testing.T) {
	d := NewPasswordProtectionDisabledDetector()
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{
			// No directorySetting was found for Password Rule Settings -
			// PasswordProtectionEnabled stays nil, Azure's own default
			// applies (protection ON). Must NOT fire.
			PasswordProtectionEnabled: nil,
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding row, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("false positive: Count=%d with no measured evidence that protection is disabled", findings[0].Count)
	}
}

func TestPasswordProtectionDisabled_FiresWhenExplicitlyDisabled(t *testing.T) {
	d := NewPasswordProtectionDisabledDetector()
	disabled := false
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{PasswordProtectionEnabled: &disabled},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected Count=1 when EnableBannedPasswordCheck=false was actually read, got %+v", findings)
	}
}

func TestPasswordProtectionDisabled_SilentWhenExplicitlyEnabled(t *testing.T) {
	d := NewPasswordProtectionDisabledDetector()
	enabled := true
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{PasswordProtectionEnabled: &enabled},
	}

	if findings := d.Detect(context.Background(), data); findings[0].Count != 0 {
		t.Fatalf("expected Count=0 when explicitly enabled, got %+v", findings)
	}
}
