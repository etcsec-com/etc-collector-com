package laps

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestLapsLegacyAttribute_FiresOnHasLegacyBooleans: the
// detector tested c.LegacyLAPSPassword != "", but that raw password value
// field is never assigned by parser.go (which fills LAPSPassword and
// WindowsLAPSPassword instead) - so the condition was always false,
// regardless of real state. The already-correct presence signal
// (HasLegacyLAPS/HasWindowsLAPS, derived from expiry attributes readable
// without special rights, and already correctly assigned by the parser)
// is what the detector should read.
func TestLapsLegacyAttribute_FiresOnHasLegacyBooleans(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{SAMAccountName: "legacy1$", HasLegacyLAPS: true, HasWindowsLAPS: false},
			{SAMAccountName: "modern1$", HasLegacyLAPS: false, HasWindowsLAPS: true},
			{SAMAccountName: "both1$", HasLegacyLAPS: true, HasWindowsLAPS: true},
		},
	}

	findings := NewLapsLegacyAttributeDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (only legacy1, legacy without windows LAPS), got %d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "legacy1$" {
		t.Fatalf("expected legacy1$ as the sole affected entity, got %+v", findings[0].AffectedEntities)
	}
}
