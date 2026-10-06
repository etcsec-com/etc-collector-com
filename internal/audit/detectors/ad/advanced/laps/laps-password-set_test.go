package laps

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Computer.LegacyLAPSPassword is declared on the type but never assigned by
// any provider - the LDAP parser fills Computer.LAPSPassword (legacy) and
// Computer.WindowsLAPSPassword (modern) instead, deriving HasLegacyLAPS /
// HasWindowsLAPS from those. A computer with legacy LAPS actually deployed
// therefore always has LegacyLAPSPassword=="" (the old, always-false
// condition) even though HasLegacyLAPS is true. This test fails against the
// old raw-value-field check (Count=0) and passes once the detector reads
// the presence booleans instead (Count=1).
func TestLapsPasswordSet_DetectsLegacyLAPSViaPresenceBoolean(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:            "CN=PC01,DC=test,DC=local",
				HasLegacyLAPS: true,
				// LegacyLAPSPassword deliberately left empty - no provider
				// ever assigns it, this mirrors real collected data.
			},
		},
	}

	findings := NewLapsPasswordSetDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (legacy LAPS computer should be counted)", findings[0].Count)
	}
}
