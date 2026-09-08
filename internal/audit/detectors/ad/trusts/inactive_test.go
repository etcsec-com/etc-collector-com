package trusts

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestInactiveDetector_FlagsStaleTrust covers a bug where the detector's
// loop was entirely commented out, so affectedNames stayed empty and
// Count was hardcoded to 0 regardless of trust state (never a legitimate
// "no stale trusts" zero). Uses PasswordLastSet (already collected for
// ANSSI R42) as a real proxy: Windows auto-rotates a trust's inter-domain
// password every 30 days while the trust is alive, so a stale
// PasswordLastSet indicates either broken rotation or an abandoned trust.
func TestInactiveDetector_FlagsStaleTrust(t *testing.T) {
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	staleTrust := types.Trust{
		TargetDomain:    "stale.example.com",
		PasswordLastSet: now.AddDate(0, 0, -400), // way past the 180-day threshold
	}
	freshTrust := types.Trust{
		TargetDomain:    "fresh.example.com",
		PasswordLastSet: now.AddDate(0, 0, -10), // rotated recently, not inactive
	}
	unreadableTrust := types.Trust{
		TargetDomain: "unreadable.example.com",
		// PasswordLastSet left zero-value: LDAP attribute unreadable/not
		// collected. Must be skipped, never guessed as inactive.
	}

	data := &audit.DetectorData{
		IncludeDetails: true,
		Now:            now,
		Trusts:         []types.Trust{staleTrust, freshTrust, unreadableTrust},
	}

	findings := NewInactiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (only the stale trust)", f.Count)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].DisplayName != "stale.example.com" {
		t.Fatalf("AffectedEntities = %+v, want exactly [stale.example.com]", f.AffectedEntities)
	}
}

// TestInactiveDetector_NoStaleTrustsIsLegitimateZero pins Count=0 as a real
// "nothing to report" outcome once the detector can actually evaluate
// trusts, distinguishing it from the previous always-zero dead code.
func TestInactiveDetector_NoStaleTrustsIsLegitimateZero(t *testing.T) {
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Trusts: []types.Trust{
			{TargetDomain: "fresh.example.com", PasswordLastSet: now.AddDate(0, 0, -5)},
		},
	}

	findings := NewInactiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected a single finding with Count=0, got %+v", findings)
	}
}
