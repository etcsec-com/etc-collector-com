package gpo

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestWSUSHTTP_Branches is coverage-only: this detector had never been
// exercised by a unit test at all (no plant/revert, never observed firing on
// the lab). The underlying logic already matches Microsoft's documented
// "Specify intranet Microsoft update service location" GPO (WUServer under
// HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate) - no code defect
// found, so this pins the positive (http://) and negative (https://, unset)
// branches with synthetic GPO data.
func TestWSUSHTTP_Branches(t *testing.T) {
	cases := []struct {
		name      string
		wuServer  *string
		wantCount int
	}{
		{"not configured (public Windows Update)", nil, 0},
		{"https:// WSUS", strPtr("https://wsus.corp.local:8531"), 0},
		{"http:// WSUS", strPtr("http://wsus.corp.local:8530"), 1},
		{"HTTP:// mixed case", strPtr("HTTP://wsus.corp.local:8530"), 1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := &audit.DetectorData{
				GPOPolicies: map[string]*audit.GPOPolicy{
					"{GUID}": {RegistrySettings: &audit.RegistrySettings{WUServer: c.wuServer}},
				},
			}
			findings := NewWSUSHTTPDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d", len(findings))
			}
			if findings[0].Count != c.wantCount {
				t.Fatalf("Count = %d, want %d", findings[0].Count, c.wantCount)
			}
			if c.wantCount == 1 {
				url, _ := findings[0].Details["wsusURL"].(string)
				if url != *c.wuServer {
					t.Fatalf("Details[wsusURL] = %q, want %q", url, *c.wuServer)
				}
			}
		})
	}
}
