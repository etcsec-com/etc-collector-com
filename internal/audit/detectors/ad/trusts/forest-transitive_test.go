package trusts

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestForestTransitiveDetector covers the base detection logic: only Forest
// trusts are flagged.
func TestForestTransitiveDetector(t *testing.T) {
	cases := []struct {
		name      string
		trusts    []types.Trust
		wantCount int
		wantNames []string
	}{
		{
			name: "forest trust flagged",
			trusts: []types.Trust{
				{TargetDomain: "otherforest.example", TrustType: "Forest"},
			},
			wantCount: 1,
			wantNames: []string{"otherforest.example"},
		},
		{
			name: "external trust not flagged (not Forest)",
			trusts: []types.Trust{
				{TargetDomain: "partner.example", TrustType: "External"},
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
			d := NewForestTransitiveDetector()
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

// TestForestTransitiveDetector_EntityNameInJSON: marshalTrust
// (pkg/types/finding.go) serializes only Type and Name, never DisplayName -
// an entity built with DisplayName instead of Name marshals with no name at
// all. Asserted on the actual json.Marshal output, at the literal fixture
// name, not by comparing Go struct fields to each other.
func TestForestTransitiveDetector_EntityNameInJSON(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Trusts: []types.Trust{
			{TargetDomain: "otherforest.example", TrustType: "Forest"},
		},
	}
	findings := NewForestTransitiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 || len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("expected exactly 1 finding with 1 entity, got %+v", findings)
	}
	raw, err := json.Marshal(findings[0].AffectedEntities[0])
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"name":"otherforest.example"`) {
		t.Fatalf("marshaled entity = %s, want to contain \"name\":\"otherforest.example\"", raw)
	}
}
