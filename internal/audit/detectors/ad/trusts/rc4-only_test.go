package trusts

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestRC4OnlyDetector covers a bug where the detection body was
// commented-out pseudo-code referencing a SupportedEncryptionTypes field
// the Trust struct never had, so affectedNames stayed empty and Count was
// always 0 regardless of the data fed in. The AESEnabled/RC4Enabled
// booleans the detector needed were already populated by the LDAP
// provider (client.go trustEncryptionFlags) but never read here.
func TestRC4OnlyDetector(t *testing.T) {
	cases := []struct {
		name      string
		trusts    []types.Trust
		wantCount int
		wantNames []string
	}{
		{
			name: "RC4-only trust (RC4 enabled, AES not) fires",
			trusts: []types.Trust{
				{TargetDomain: "legacy.corp", RC4Enabled: true, AESEnabled: false},
			},
			wantCount: 1,
			wantNames: []string{"legacy.corp"},
		},
		{
			name: "trust with both RC4 and AES does not fire (not RC4-only)",
			trusts: []types.Trust{
				{TargetDomain: "modern.corp", RC4Enabled: true, AESEnabled: true},
			},
			wantCount: 0,
		},
		{
			name: "trust with neither flag set (attribute unset/unreported) does not fire",
			trusts: []types.Trust{
				{TargetDomain: "unknown.corp", RC4Enabled: false, AESEnabled: false},
			},
			wantCount: 0,
		},
		{
			name: "AES-only trust does not fire",
			trusts: []types.Trust{
				{TargetDomain: "aes.corp", RC4Enabled: false, AESEnabled: true},
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
			d := NewRC4OnlyDetector()
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
