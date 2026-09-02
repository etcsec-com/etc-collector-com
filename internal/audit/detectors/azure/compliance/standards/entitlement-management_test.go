package standards

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// B_075/T_069 — "couldn't probe" must be visible in the report, distinct from
// both a real finding and real silence: an Info-severity finding, not nil.
func TestEntitlementManagement_InfoFindingWhenNotProbed(t *testing.T) {
	d := NewEntitlementManagementDetector()
	data := &audit.DetectorData{} // AzureAccessPackagesProbed false — couldn't check

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (visible ignorance) when the endpoint was never probed, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityInfo {
		t.Fatalf("expected Info severity for an unprobed check, got %s", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Title, "not determinable") {
		t.Fatalf("title must say the check wasn't determinable, got %q", findings[0].Title)
	}
}

func TestEntitlementManagement_SilentWhenConfigured(t *testing.T) {
	d := NewEntitlementManagementDetector()
	data := &audit.DetectorData{AzureAccessPackagesProbed: true, AzureAccessPackagesCount: 2}

	if findings := d.Detect(context.Background(), data); len(findings) != 0 {
		t.Fatalf("expected no finding when access packages exist, got %+v", findings)
	}
}

func TestEntitlementManagement_FiresWhenProbedAndEmpty(t *testing.T) {
	d := NewEntitlementManagementDetector()
	data := &audit.DetectorData{AzureAccessPackagesProbed: true, AzureAccessPackagesCount: 0}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when probed and genuinely empty, got %d", len(findings))
	}
}
