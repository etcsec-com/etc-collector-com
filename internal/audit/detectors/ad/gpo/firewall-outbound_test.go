package gpo

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestFirewallOutbound_BlockSemanticsRegression freezes the correct
// Microsoft semantics for `DefaultOutboundAction`: 1 = block (secure),
// 0 = allow (default permissive). The deleted PA038_FIREWALL_OUTBOUND
// detector inverted these values and produced false positives in
// production from v3.1.17 to v3.1.20. This test prevents the inversion
// from sneaking back into the surviving custom detector.
func TestFirewallOutbound_BlockSemanticsRegression(t *testing.T) {
	d := NewFirewallOutboundDetector()
	one := 1
	zero := 0

	cases := []struct {
		name      string
		value     *int
		wantCount int
	}{
		// 1 = block (correct, secure). Detector must NOT flag.
		{"value=1 (block)", &one, 0},
		// 0 = allow (Windows default permissive). Detector MUST flag.
		{"value=0 (allow)", &zero, 1},
		// nil = no GPO sets it = Windows default = allow. Detector MUST flag.
		{"value=nil (default allow)", nil, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{
				GPOPolicies: map[string]*audit.GPOPolicy{
					"GUID": {
						RegistrySettings: &audit.RegistrySettings{
							FirewallOutboundAction: tc.value,
						},
					},
				},
			}
			findings := d.Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Fatalf("expected count=%d, got %d (semantics inversion regression?)",
					tc.wantCount, findings[0].Count)
			}
		})
	}
}
