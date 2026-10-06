package trusts

import (
	"context"
	"encoding/json"
	"strings"
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
					if f.AffectedEntities[i].Name != name {
						t.Fatalf("AffectedEntities[%d].Name = %q, want %q", i, f.AffectedEntities[i].Name, name)
					}
				}
			}
		})
	}
}

// TestRC4OnlyDetector_EntityNameInJSON: marshalTrust
// (pkg/types/finding.go) serializes only Type and Name, never DisplayName -
// an entity built with DisplayName instead of Name marshals with no name at
// all. Asserted on the actual json.Marshal output, at the literal fixture
// name, not by comparing Go struct fields to each other.
func TestRC4OnlyDetector_EntityNameInJSON(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Trusts: []types.Trust{
			{TargetDomain: "legacy.corp", RC4Enabled: true, AESEnabled: false},
		},
	}
	findings := NewRC4OnlyDetector().Detect(context.Background(), data)
	if len(findings) != 1 || len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("expected exactly 1 finding with 1 entity, got %+v", findings)
	}
	raw, err := json.Marshal(findings[0].AffectedEntities[0])
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"name":"legacy.corp"`) {
		t.Fatalf("marshaled entity = %s, want to contain \"name\":\"legacy.corp\"", raw)
	}
}
