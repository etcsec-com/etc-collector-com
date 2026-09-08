package cis

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func intp(v int) *int { return &v }

func gpoWith(rs *audit.RegistrySettings) map[string]*audit.GPOPolicy {
	return map[string]*audit.GPOPolicy{
		"{gpo}": {GUID: "{gpo}", DisplayName: "Default Domain Controllers Policy", RegistrySettings: rs},
	}
}

// TestNetworkSecurity_NoGPODataAtAll_NoFalsePositive: when
// data.GPOPolicies is nil (SMB/SYSVOL not collected this run), the 4
// registry-based checks must not be evaluated at all - "never looked" is not
// "looked and found nothing configured".
func TestNetworkSecurity_NoGPODataAtAll_NoFalsePositive(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: nil}
	findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0 when no GPO data was collected", findings)
	}
}

// TestNetworkSecurity_ConfiguredButAbsentSetting_Flagged: a
// domain WAS audited (GPO data collected) but a specific setting was never
// explicitly configured. CIS Benchmark items read "Ensure X is set to Y" -
// not configured is a finding, not a silent pass. Before the fix, a nil
// RequireSMBSigningServer was treated as compliant.
func TestNetworkSecurity_ConfiguredButAbsentSetting_Flagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{})}
	findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	// All 4 registry checks should be flagged since none is configured.
	if findings[0].Count != 4 {
		t.Errorf("Count = %d, want 4 (all 4 unconfigured registry settings flagged)", findings[0].Count)
	}
}

// TestNetworkSecurity_FullyCompliant_NoFinding is the regression check for a
// properly configured domain.
func TestNetworkSecurity_FullyCompliant_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: gpoWith(&audit.RegistrySettings{
			RequireSMBSigningServer: intp(1),
			RequireSMBSigningClient: intp(1),
			LDAPServerIntegrity:     intp(2),
			LDAPChannelBinding:      intp(2),
		}),
		DomainInfo: &types.DomainInfo{FunctionalLevelInt: 7},
	}
	findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0 for a fully compliant domain", findings)
	}
}

// TestNetworkSecurity_FunctionalLevel_NotAttributedToCIS: no CIS
// Windows Server Benchmark contains a domain-functional-level control. This
// product-level check must not be labeled as a CIS requirement.
func TestNetworkSecurity_FunctionalLevel_NotAttributedToCIS(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: gpoWith(&audit.RegistrySettings{
			RequireSMBSigningServer: intp(1),
			RequireSMBSigningClient: intp(1),
			LDAPServerIntegrity:     intp(2),
			LDAPChannelBinding:      intp(2),
		}),
		DomainInfo: &types.DomainInfo{FunctionalLevelInt: 3},
	}
	findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (only the functional-level note)", findings)
	}
	violations, _ := findings[0].Details["violations"].([]string)
	if len(violations) != 1 || violations[0][:4] == "CIS " {
		t.Errorf("functional-level violation must not be attributed to CIS, got %v", violations)
	}
}

// TestNetworkSecurity_LDAPSigningCitesServerSideSection: the
// old citation "CIS 2.3.11.8" is the LDAP CLIENT signing control; this
// detector reads the SERVER-side (Domain controller) setting, which belongs
// under section 2.3.5.
func TestNetworkSecurity_LDAPSigningCitesServerSideSection(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{
		RequireSMBSigningServer: intp(1),
		RequireSMBSigningClient: intp(1),
		LDAPChannelBinding:      intp(2),
		LDAPServerIntegrity:     intp(0),
	})}
	findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
	violations, _ := findings[0].Details["violations"].([]string)
	found := false
	for _, v := range violations {
		if v == "CIS 2.3.5 (Domain controller: LDAP server signing requirements): not set to Require signing" {
			found = true
		}
		if len(v) >= 14 && v[:14] == "CIS 2.3.11.8: " {
			t.Errorf("violation still cites the wrong (client-side) CIS section: %q", v)
		}
	}
	if !found {
		t.Errorf("expected the corrected 2.3.5 LDAP server-signing violation, got %v", violations)
	}
}
