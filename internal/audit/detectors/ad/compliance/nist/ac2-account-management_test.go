package nist

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAC2AccountManagement_LastLogonTimestampMoreRecent_NotFlagged is a
// red->green test for the non-replicated lastLogon bug: a user whose
// lastLogon (this DC's own view) is stale but whose lastLogonTimestamp
// (replicated) is recent must not be counted as inactive.
func TestAC2AccountManagement_LastLogonTimestampMoreRecent_NotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	stale := now.AddDate(0, 0, -91)
	recent := now.AddDate(0, 0, -5)

	d := NewAC2AccountManagementDetector()
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "multi_dc_user", LastLogon: stale, LastLogonTimestamp: recent},
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	got, _ := findings[0].Details["inactiveAccounts"].(int)
	if got != 0 {
		t.Errorf("inactiveAccounts = %d, want 0 - lastLogonTimestamp shows recent activity even though this DC's own lastLogon is stale", got)
	}
}

// TestAC2AccountManagement_NoNISTMandatedThresholdClaim is a
// red->green test for the framing fix: NIST SP 800-53 Rev 5 AC-2 leaves its
// thresholds organization-defined, so the description must not claim these
// specific numbers are themselves NIST requirements.
func TestAC2AccountManagement_NoNISTMandatedThresholdClaim(t *testing.T) {
	d := NewAC2AccountManagementDetector()
	findings := d.Detect(context.Background(), &audit.DetectorData{Now: time.Now()})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Description, "organization-defined") {
		t.Errorf("description should disclose that AC-2's thresholds are organization-defined, not NIST-mandated exact numbers, got %q", findings[0].Description)
	}
}
