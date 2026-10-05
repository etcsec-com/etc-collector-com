package medium

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestTrustLateralDetector covers the fact that PATH_TRUST_LATERAL read
// t.SIDFilteringEnabled/t.SelectiveAuthEnabled - distinct, never-assigned
// alias fields on types.Trust - instead of t.SIDFiltering/t.SelectiveAuth,
// the fields the LDAP provider actually populates. Since the Enabled
// aliases are always false (zero value), `noSidFiltering := !t.SIDFilteringEnabled`
// was always true, so the detector unconditionally flagged every trust
// regardless of its real configuration.
func TestTrustLateralDetector(t *testing.T) {
	cases := []struct {
		name      string
		trusts    []types.Trust
		wantCount int
	}{
		{
			name: "SID filtering ON, non-forest trust -> not flagged",
			trusts: []types.Trust{
				{Name: "partner.corp", SIDFiltering: true, SelectiveAuth: false, TrustType: "External", TrustDirection: "Bidirectional", TrustDirectionInt: 3},
			},
			wantCount: 0,
		},
		{
			name: "SID filtering OFF -> flagged",
			trusts: []types.Trust{
				{Name: "legacy.corp", SIDFiltering: false, SelectiveAuth: true, TrustType: "External", TrustDirection: "Outbound", TrustDirectionInt: 2},
			},
			wantCount: 1,
		},
		{
			name: "SID filtering ON, bidirectional forest trust WITH selective auth -> not flagged",
			trusts: []types.Trust{
				{Name: "forest.corp", SIDFiltering: true, SelectiveAuth: true, TrustType: "Forest", TrustDirection: "Bidirectional", TrustDirectionInt: 3},
			},
			wantCount: 0,
		},
		{
			name: "SID filtering ON, bidirectional forest trust WITHOUT selective auth -> flagged",
			trusts: []types.Trust{
				{Name: "openforest.corp", SIDFiltering: true, SelectiveAuth: false, TrustType: "Forest", TrustDirection: "Bidirectional", TrustDirectionInt: 3},
			},
			wantCount: 1,
		},
		{
			name: "SID filtering ON, unidirectional forest trust without selective auth -> not flagged (not bidirectional)",
			trusts: []types.Trust{
				{Name: "oneway.corp", SIDFiltering: true, SelectiveAuth: false, TrustType: "Forest", TrustDirection: "Outbound", TrustDirectionInt: 2},
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
			d := NewTrustLateralDetector()
			data := &audit.DetectorData{
				Trusts:         c.trusts,
				IncludeDetails: true,
			}
			findings := d.Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding wrapper, got %d", len(findings))
			}
			if findings[0].Count != c.wantCount {
				t.Fatalf("Count = %d, want %d", findings[0].Count, c.wantCount)
			}
		})
	}
}
