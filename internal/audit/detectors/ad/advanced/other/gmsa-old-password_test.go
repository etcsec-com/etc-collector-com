package other

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestGMSAOldPassword_ReadsFromComputers covers a bug where the detector
// used to read data.Users + user.IsGMSA, a chain GetUsers'
// (objectCategory=person) filter makes structurally unreachable - a gMSA
// object never has objectCategory=person, so IsGMSA could never be true on
// any entry ever placed in data.Users. gMSA objects are actually collected
// into data.Computers (they inherit "computer" in the AD schema). This
// test puts the stale gMSA only in data.Computers (IsGMSA=true, as
// parseComputer now sets it from the objectClass list) and data.Users
// empty - the old code loops data.Users and reports Count=0 no matter how
// stale the password is.
func TestGMSAOldPassword_ReadsFromComputers(t *testing.T) {
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	stalePwd := now.AddDate(0, 0, -90) // 90 days old, past the 60-day threshold

	data := &audit.DetectorData{
		Now:            now,
		IncludeDetails: true,
		Computers: []types.Computer{
			{SAMAccountName: "svc-backup$", IsGMSA: true, PasswordLastSet: stalePwd},
			{SAMAccountName: "WKS01$", IsGMSA: false, PasswordLastSet: stalePwd}, // ordinary computer, must not count
		},
	}

	d := NewGMSAOldPasswordDetector()
	findings := d.Detect(context.Background(), data)

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 for the one stale gMSA, got %d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("expected 1 affected entity, got %d", len(findings[0].AffectedEntities))
	}
}

// TestGMSAOldPassword_FreshPasswordDoesNotFire guards against
// over-filtering: a gMSA with a recently rotated password must not fire.
func TestGMSAOldPassword_FreshPasswordDoesNotFire(t *testing.T) {
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	freshPwd := now.AddDate(0, 0, -10)

	data := &audit.DetectorData{
		Now:       now,
		Computers: []types.Computer{{SAMAccountName: "svc-fresh$", IsGMSA: true, PasswordLastSet: freshPwd}},
	}

	d := NewGMSAOldPasswordDetector()
	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0, got %d", findings[0].Count)
	}
}
