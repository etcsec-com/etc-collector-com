package gpo

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestSeDebugAbuse_FlagsLocalAndNetworkService covers an ecart: the detector
// used to share safePrivilegeSIDs (Administrators, SYSTEM, LOCAL SERVICE,
// NETWORK SERVICE) with the unrelated SeLoadDriverPrivilege check, treating
// LOCAL SERVICE (S-1-5-19) and NETWORK SERVICE (S-1-5-20) as safe holders of
// SeDebugPrivilege. Per Microsoft's Win32 "LocalService Account" /
// "NetworkService Account" references, neither account carries SE_DEBUG_NAME
// in its default privilege set (unlike LocalSystem, which does) - so a GPO
// explicitly granting SeDebugPrivilege to either is a real, dangerous
// widening (LSASS memory access from a compromised, network-facing service
// account) that the old shared allowlist silently cleared. This test fails
// against the old shared safePrivilegeSIDs allowlist (which would report
// Count=0 for a NETWORK SERVICE grant) and passes once SeDebugPrivilege uses
// its own, narrower safe set.
func TestSeDebugAbuse_FlagsLocalAndNetworkService(t *testing.T) {
	cases := []struct {
		name      string
		sids      []string
		wantCount int
	}{
		{"Administrators only - safe", []string{"S-1-5-32-544"}, 0},
		{"SYSTEM only - safe (inherent privilege)", []string{"S-1-5-18"}, 0},
		{"Administrators + SYSTEM - safe", []string{"S-1-5-32-544", "S-1-5-18"}, 0},
		{"NETWORK SERVICE granted - unsafe", []string{"S-1-5-32-544", "S-1-5-20"}, 1},
		{"LOCAL SERVICE granted - unsafe", []string{"S-1-5-32-544", "S-1-5-19"}, 1},
		{"ordinary user granted - unsafe", []string{"S-1-5-32-544", "S-1-5-21-1-2-3-1104"}, 1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := &audit.DetectorData{
				GPOPolicies: map[string]*audit.GPOPolicy{
					"{GUID}": {PrivilegeRights: &audit.PrivilegeRights{SeDebugPrivilege: c.sids}},
				},
			}
			findings := NewSeDebugAbuseDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d", len(findings))
			}
			if findings[0].Count != c.wantCount {
				t.Fatalf("Count = %d, want %d (sids=%v)", findings[0].Count, c.wantCount, c.sids)
			}
		})
	}
}
