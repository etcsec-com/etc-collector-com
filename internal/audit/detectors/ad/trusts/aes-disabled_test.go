package trusts

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAESDisabledDetector covers the fact that the detector used to measure
// SIDFiltering/SelectiveAuth (neither related to encryption) instead of the
// AESEnabled field the LDAP provider has populated from
// msDS-SupportedEncryptionTypes. The old heuristic flagged a
// trust with AES enabled but no SID filtering, and cleared a trust with AES
// disabled but SID filtering on - the opposite of what the title promises.
func TestAESDisabledDetector(t *testing.T) {
	cases := []struct {
		name      string
		trusts    []types.Trust
		wantCount int
		wantNames []string
	}{
		{
			name: "AES disabled, SID filtering and selective auth ON - still flagged",
			trusts: []types.Trust{
				{TargetDomain: "hardened.corp", AESEnabled: false, SIDFiltering: true, SelectiveAuth: true},
			},
			wantCount: 1,
			wantNames: []string{"hardened.corp"},
		},
		{
			name: "AES enabled, SID filtering and selective auth OFF - not flagged",
			trusts: []types.Trust{
				{TargetDomain: "modern.corp", AESEnabled: true, SIDFiltering: false, SelectiveAuth: false},
			},
			wantCount: 0,
		},
		{
			name: "AES enabled - not flagged regardless of other attributes",
			trusts: []types.Trust{
				{TargetDomain: "aes.corp", AESEnabled: true, SIDFiltering: true, SelectiveAuth: true},
			},
			wantCount: 0,
		},
		{
			name:      "no trusts",
			trusts:    nil,
			wantCount: 0,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := NewAESDisabledDetector()
			data := &audit.DetectorData{
				Trusts:         c.trusts,
				IncludeDetails: true,
			}
			findings := d.Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding wrapper, got %d", len(findings))
			}
			f := findings[0]
			if f.Count != c.wantCount {
				t.Fatalf("Count = %d, want %d", f.Count, c.wantCount)
			}
			if c.wantCount > 0 {
				if len(f.AffectedEntities) != c.wantCount {
					t.Fatalf("AffectedEntities len = %d, want %d", len(f.AffectedEntities), c.wantCount)
				}
				for i, name := range c.wantNames {
					if f.AffectedEntities[i].DisplayName != name {
						t.Fatalf("AffectedEntities[%d].DisplayName = %q, want %q", i, f.AffectedEntities[i].DisplayName, name)
					}
				}
			}
		})
	}
}
