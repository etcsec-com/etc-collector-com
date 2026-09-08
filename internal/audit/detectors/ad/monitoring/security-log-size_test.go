package monitoring

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestSecurityLogSize_CISThreshold locks the minimum to the CIS Microsoft
// Windows Server Benchmark value (196608 KB / 192 MB). A config between the
// old 128 MB floor and the CIS 192 MB floor must now be flagged.
func TestSecurityLogSize_CISThreshold(t *testing.T) {
	d := NewSecurityLogSizeDetector()

	cases := []struct {
		name      string
		sizeKB    int
		wantCount int
	}{
		{"150 MB: below CIS minimum, must be flagged", 150 * 1024, 1},
		{"192 MB: exactly at CIS minimum, must not be flagged", 196608, 0},
		{"256 MB: above CIS minimum, must not be flagged", 256 * 1024, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			size := tc.sizeKB
			data := &audit.DetectorData{
				GPOPolicies: map[string]*audit.GPOPolicy{
					"GUID": {
						RegistrySettings: &audit.RegistrySettings{SecurityLogMaxSizeKB: &size},
					},
				},
			}
			findings := d.Detect(context.Background(), data)
			if findings[0].Count != tc.wantCount {
				t.Fatalf("expected count=%d, got %d", tc.wantCount, findings[0].Count)
			}
		})
	}
}
