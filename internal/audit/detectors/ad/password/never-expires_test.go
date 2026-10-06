package password

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestNeverExpires_DisabledAccountExcluded pins the fix: a disabled account
// carrying DONT_EXPIRE_PASSWD (0x10000) cannot authenticate today, so it must
// not inflate the Critical population - it is reported separately by
// NeverExpiresOnDisabledAccountDetector instead.
//
// Fixtures use realistic multi-bit UAC values (0x10200 = NORMAL_ACCOUNT |
// DONT_EXPIRE_PASSWD, active ; 0x10202 = same | ACCOUNTDISABLE, disabled)
// rather than the bare 0x10000 literal: a mono-bit fixture cannot tell
// `(uac & 0x10000) != 0` apart from `uac == 0x10000` - a stray equality
// check that a mono-bit fixture can never expose.
func TestNeverExpires_DisabledAccountExcluded(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "active-svc", UserAccountControl: 0x10200, Disabled: false},
			{SAMAccountName: "stale-disabled", UserAccountControl: 0x10202, Disabled: true},
		},
	}

	findings := NewNeverExpiresDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled account must be excluded)", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Fatalf("Severity = %s, want critical", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "active-svc" {
		t.Fatalf("AffectedEntities = %+v, want only active-svc", findings[0].AffectedEntities)
	}
}

// TestNeverExpires_FlagNotSetNotFlagged guards the negative case.
func TestNeverExpires_FlagNotSetNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "ordinary", UserAccountControl: 0x0200}}, // NORMAL_ACCOUNT
	}

	findings := NewNeverExpiresDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}
