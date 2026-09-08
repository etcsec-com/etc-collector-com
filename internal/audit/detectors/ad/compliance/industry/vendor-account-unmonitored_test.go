package industry

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestVendorAccountUnmonitored_SeverityIsLowNotMedium and the title check
// below are the red->green test: before the fix this fired
// SeverityMedium under a title claiming vendor accounts were confirmed
// "unmonitored" - a status this detector never measures (it's a
// SAMAccountName/Description naming-pattern match, dominated in practice by
// ordinary "service" accounts, 0/12 precision for real vendor accounts on
// the lab domain). Severity must drop to Low and the title must stop
// asserting "UNMONITORED"/"Monitoring Review" as an established fact.
func TestVendorAccountUnmonitored_SeverityIsLowNotMedium(t *testing.T) {
	d := NewVendorAccountUnmonitoredDetector()
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "backup-service", Disabled: false},
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected the 'service' pattern to match svc-backup, got Count=%d", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityLow {
		t.Errorf("Severity = %q, want %q (naming heuristic, not a confirmed monitoring-status violation)", findings[0].Severity, types.SeverityLow)
	}
	if strings.Contains(findings[0].Title, "Vendor Account Monitoring Review") {
		t.Errorf("Title still claims monitoring status was reviewed/confirmed: %q", findings[0].Title)
	}
}
