package kerberos

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestKerberoasting_Tier0Split verifies that KERBEROASTING_RISK partitions
// Kerberoastable accounts by Tier 0 membership (recursive group expansion +
// AdminCount=1 + tier0_groups.yaml customer overrides) and emits a separate
// Critical finding for Tier 0 hits — matching the scope of the deleted
// ANSSI_R69_TIER0_SPN_EXPOSED detector. v3.1.21 migration coverage.
func TestKerberoasting_Tier0Split(t *testing.T) {
	tier0DN := "CN=alice,OU=Admins,DC=test,DC=local"
	svcDN := "CN=svc,OU=Services,DC=test,DC=local"

	cases := []struct {
		name            string
		data            *audit.DetectorData
		wantTier0Count  int
		wantOthersCount int
		wantTier0Sev    types.Severity
		wantOthersSev   types.Severity
	}{
		{
			name: "Tier 0 admin with SPN → 1 Critical finding only",
			data: &audit.DetectorData{
				Groups: []types.Group{
					{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local", Members: []string{tier0DN}},
				},
				Users: []types.User{
					{DN: tier0DN, SAMAccountName: "alice", ServicePrincipalNames: []string{"http/web01"}},
				},
				IncludeDetails: true,
			},
			wantTier0Count: 1,
			wantTier0Sev:   types.SeverityCritical,
		},
		{
			name: "Service account with SPN (non-Tier 0) → 1 High finding only",
			data: &audit.DetectorData{
				Groups: []types.Group{
					{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local", Members: nil},
				},
				Users: []types.User{
					{DN: svcDN, SAMAccountName: "svc", ServicePrincipalNames: []string{"http/web01"}},
				},
			},
			wantOthersCount: 1,
			wantOthersSev:   types.SeverityHigh,
		},
		{
			name: "Both Tier 0 and non-Tier 0 → 2 distinct findings",
			data: &audit.DetectorData{
				Groups: []types.Group{
					{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local", Members: []string{tier0DN}},
				},
				Users: []types.User{
					{DN: tier0DN, SAMAccountName: "alice", ServicePrincipalNames: []string{"http/web01"}},
					{DN: svcDN, SAMAccountName: "svc", ServicePrincipalNames: []string{"mssql/db01"}},
				},
			},
			wantTier0Count:  1,
			wantTier0Sev:    types.SeverityCritical,
			wantOthersCount: 1,
			wantOthersSev:   types.SeverityHigh,
		},
		{
			name: "No Kerberoastable accounts → no findings",
			data: &audit.DetectorData{
				Users: []types.User{
					{DN: svcDN, SAMAccountName: "svc"}, // no SPN
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewKerberoastingRiskDetector()
			findings := d.Detect(context.Background(), tc.data)

			var tier0F, othersF *types.Finding
			for i := range findings {
				if findings[i].Severity == types.SeverityCritical {
					tier0F = &findings[i]
				} else {
					othersF = &findings[i]
				}
			}

			if tc.wantTier0Count == 0 && tier0F != nil {
				t.Errorf("expected no Tier 0 finding, got %+v", tier0F)
			}
			if tc.wantTier0Count > 0 {
				if tier0F == nil {
					t.Errorf("expected Tier 0 finding (count=%d, sev=%s), got nil", tc.wantTier0Count, tc.wantTier0Sev)
				} else if tier0F.Count != tc.wantTier0Count || tier0F.Severity != tc.wantTier0Sev {
					t.Errorf("Tier 0 finding mismatch: got count=%d sev=%s, want count=%d sev=%s",
						tier0F.Count, tier0F.Severity, tc.wantTier0Count, tc.wantTier0Sev)
				}
			}
			if tc.wantOthersCount == 0 && othersF != nil {
				t.Errorf("expected no non-Tier-0 finding, got %+v", othersF)
			}
			if tc.wantOthersCount > 0 {
				if othersF == nil {
					t.Errorf("expected non-Tier-0 finding (count=%d, sev=%s), got nil", tc.wantOthersCount, tc.wantOthersSev)
				} else if othersF.Count != tc.wantOthersCount || othersF.Severity != tc.wantOthersSev {
					t.Errorf("non-Tier-0 finding mismatch: got count=%d sev=%s, want count=%d sev=%s",
						othersF.Count, othersF.Severity, tc.wantOthersCount, tc.wantOthersSev)
				}
			}
		})
	}
}
