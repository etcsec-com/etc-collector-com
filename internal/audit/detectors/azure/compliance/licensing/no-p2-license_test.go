package licensing

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// B_158/T_058 — the detector used to fire on every tenant unconditionally.
// This is the acceptance criterion's own case: "AZ_NO_P2_LICENSE ne fire
// plus sur un tenant dont licenseInfo indique un P2 actif".
func TestNoP2License_SilentWhenP2Active(t *testing.T) {
	d := NewNoP2LicenseDetector()
	data := &audit.DetectorData{AzureLicenseTier: "p2"}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding on a P2 tenant, got %+v", findings)
	}
}

func TestNoP2License_FiresWhenFree(t *testing.T) {
	d := NewNoP2LicenseDetector()
	data := &audit.DetectorData{AzureLicenseTier: "free"}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding on a free tenant, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1", findings[0].Count)
	}
}

func TestNoP2License_FiresWhenP1(t *testing.T) {
	d := NewNoP2LicenseDetector()
	data := &audit.DetectorData{AzureLicenseTier: "p1"}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding on a P1-only tenant, got %d", len(findings))
	}
}
