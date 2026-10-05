package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// --- R82/R83 relabeling ---

func denyRightsPolicy(sids ...string) map[string]*audit.GPOPolicy {
	return map[string]*audit.GPOPolicy{
		"policy-1": {
			PrivilegeRights: &audit.PrivilegeRights{
				SeDenyNetworkLogonRight:           sids,
				SeDenyInteractiveLogonRight:       sids,
				SeDenyRemoteInteractiveLogonRight: sids,
			},
		},
	}
}

func TestR82R83AdminArchitecture_Detect(t *testing.T) {
	cases := []struct {
		name     string
		policies map[string]*audit.GPOPolicy
		wantFlag bool
	}{
		{"deny rights configured for Authenticated Users -> clean", denyRightsPolicy("S-1-5-11"), false},
		{"no GPO configures deny rights -> flagged", nil, true},
		{"deny rights configured for an unrelated SID only -> flagged", denyRightsPolicy("S-1-5-32-544"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{GPOPolicies: tc.policies}
			d := NewR82R83AdminArchitectureDetector()
			findings := d.Detect(context.Background(), data)
			flagged := len(findings) == 1 && findings[0].Count > 0
			if flagged != tc.wantFlag {
				t.Errorf("flagged = %v, want %v (findings=%+v)", flagged, tc.wantFlag, findings)
			}
		})
	}
}

// this finding used to claim it measures ANSSI R82 + R83. Both are
// about restricting Tier 0's OUTBOUND connections to less-trusted zones
// (the opposite direction of a deny-inbound-logon GPO check), and the
// guide's own footnote on R83 says deny-logon GPO settings alone don't
// satisfy it. The finding must no longer attribute this check to R82/R83.
func TestR82R83AdminArchitecture_DoesNotClaimANSSIR82R83(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: nil}
	d := NewR82R83AdminArchitectureDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count == 0 {
		t.Fatalf("expected a flagged finding, got %+v", findings)
	}
	title, desc := findings[0].Title, findings[0].Description
	if strings.Contains(title, "R82") || strings.Contains(title, "R83") {
		t.Errorf("title still attributes this check to R82/R83: %q", title)
	}
	if !strings.Contains(desc, "NOT a measurement of ANSSI R82 or R83") {
		t.Errorf("description should explicitly disclaim R82/R83 attribution, got %q", desc)
	}
}
