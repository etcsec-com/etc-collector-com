package gpo

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestPrintNightmare_DescriptionScopedToCollectedValue covers an ecart: the
// old Description claimed "Point-and-Print restrictions are not configured
// to prevent PrintNightmare (CVE-2021-34527) exploitation" - an unqualified
// claim about the whole Point and Print Restrictions policy - while the
// detector only ever reads one of the two registry values Microsoft's
// KB5005010 guidance ("Restricting installation of new printer drivers
// after applying the July 6, 2021 updates") describes:
// NoWarningNoElevationOnInstall (new connections). UpdatePromptSettings
// (existing connections) is never collected (no RegistrySettings field for
// it), so a domain that hardens the first value but not the second would
// read clean here while still being exploitable via the driver-update path.
// This test fails against the old unqualified claim and passes once the
// description honestly scopes itself to what is actually measured.
func TestPrintNightmare_DescriptionScopedToCollectedValue(t *testing.T) {
	v := 1
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{GUID}": {RegistrySettings: &audit.RegistrySettings{PointAndPrintNoElevation: &v}},
		},
	}

	findings := NewPrintNightmareDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	desc := findings[0].Description

	if desc == "Point-and-Print restrictions are not configured to prevent PrintNightmare (CVE-2021-34527) exploitation. The NoWarningNoElevationOnInstall setting allows any user to install printer drivers from remote servers without elevation, enabling remote code execution as SYSTEM." {
		t.Fatalf("description still makes the old unqualified claim about Point-and-Print restrictions as a whole")
	}
	if !strings.Contains(desc, "UpdatePromptSettings") {
		t.Fatalf("description should disclose that UpdatePromptSettings (existing connections) is not evaluated, got %q", desc)
	}
	if !strings.Contains(desc, "NEW") && !strings.Contains(desc, "new") {
		t.Fatalf("description should scope the claim to new printer connections, got %q", desc)
	}
}

// TestPrintNightmare_FiresOnUnsafeValue is an unchanged-behavior regression
// pin: NoWarningNoElevationOnInstall=1 (no warning/elevation prompt) must
// still fire, per Microsoft KB5005010.
func TestPrintNightmare_FiresOnUnsafeValue(t *testing.T) {
	cases := []struct {
		name      string
		v         *int
		wantCount int
	}{
		{"unset (safe, prompt shown)", nil, 0},
		{"0 (safe, prompt shown)", intPtrPN(0), 0},
		{"1 (unsafe, no prompt)", intPtrPN(1), 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := &audit.DetectorData{
				GPOPolicies: map[string]*audit.GPOPolicy{
					"{GUID}": {RegistrySettings: &audit.RegistrySettings{PointAndPrintNoElevation: c.v}},
				},
			}
			findings := NewPrintNightmareDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d", len(findings))
			}
			if findings[0].Count != c.wantCount {
				t.Fatalf("Count = %d, want %d", findings[0].Count, c.wantCount)
			}
		})
	}
}

func intPtrPN(v int) *int { return &v }
