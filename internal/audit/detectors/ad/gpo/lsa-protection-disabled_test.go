package gpo

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// Microsoft Learn, "Configure added LSA protection": RunAsPPL=1 enables LSA
// protection with a UEFI lock, RunAsPPL=2 enables it without the UEFI lock
// (the default on new Windows Server 2025 installs, and the only value
// enforced on Windows 11 22H2+). Both are "enabled". This test fails
// against the old `*v != 1` check (RunAsPPL=2 -> false positive, Count=1)
// and passes once value 2 is also accepted (Count=0).
func TestLSAProtection_AcceptsRunAsPPLValue2(t *testing.T) {
	one := 1
	two := 2
	zero := 0

	cases := []struct {
		name      string
		v         *int
		wantCount int
	}{
		{"unset -> not enabled", nil, 1},
		{"RunAsPPL=0 explicitly off -> not enabled", &zero, 1},
		{"RunAsPPL=1 (UEFI lock) -> enabled", &one, 0},
		{"RunAsPPL=2 (no UEFI lock, WS2025 default) -> enabled", &two, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{
				GPOPolicies: map[string]*audit.GPOPolicy{
					"GUID": {
						RegistrySettings: &audit.RegistrySettings{LSARunAsPPL: tc.v},
					},
				},
			}

			findings := NewLSAProtectionDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Fatalf("Count = %d, want %d", findings[0].Count, tc.wantCount)
			}
		})
	}
}
