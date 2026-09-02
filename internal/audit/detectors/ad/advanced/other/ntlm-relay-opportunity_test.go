package other

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// T_046 / B_049 — NTLM_RELAY_OPPORTUNITY read data.DomainInfo.
// LDAPSigningRequired / .ChannelBindingRequired, two fields nothing in this
// codebase ever assigned (permanently false). isVulnerable was therefore
// always true: this fired on every single audit, unconditionally, unrelated
// to whether SYSVOL was even reachable. Now measures the same GPO registry
// keys the sibling signing detectors use, with the same "not measurable,
// don't fire" guard.

func ntlmIntPtr(v int) *int { return &v }

func detectNtlmRelay(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewNtlmRelayOpportunityDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

func TestNtlmRelayOpportunity_UnreachableSYSVOLDoesNotFire(t *testing.T) {
	f := detectNtlmRelay(t, &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: "DC=example,DC=com"},
	})
	if f.Count != 0 {
		t.Fatalf("SYSVOL unreachable must not be reported as a finding, count=%d", f.Count)
	}
}

func TestNtlmRelayOpportunity_NoDomainInfoDoesNotFire(t *testing.T) {
	f := detectNtlmRelay(t, &audit.DetectorData{IncludeDetails: true})
	if f.Count != 0 {
		t.Fatalf("no domain info must not be reported as a finding, count=%d", f.Count)
	}
}

func measuredNtlmData(mutate func(*audit.RegistrySettings)) *audit.DetectorData {
	rs := &audit.RegistrySettings{}
	if mutate != nil {
		mutate(rs)
	}
	return &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: "DC=example,DC=com"},
		GPOPolicies: map[string]*audit.GPOPolicy{
			helpers.DefaultDCPolicyGUID: {GUID: helpers.DefaultDCPolicyGUID, RegistrySettings: rs},
		},
	}
}

func TestNtlmRelayOpportunity_MeasuredBothRequiredDoesNotFire(t *testing.T) {
	f := detectNtlmRelay(t, measuredNtlmData(func(rs *audit.RegistrySettings) {
		rs.LDAPServerIntegrity = ntlmIntPtr(2)
		rs.LDAPChannelBinding = ntlmIntPtr(2)
	}))
	if f.Count != 0 {
		t.Fatalf("both measured + required must not fire, count=%d", f.Count)
	}
}

func TestNtlmRelayOpportunity_MeasuredSigningNotRequiredFires(t *testing.T) {
	f := detectNtlmRelay(t, measuredNtlmData(func(rs *audit.RegistrySettings) {
		rs.LDAPServerIntegrity = ntlmIntPtr(1)
		rs.LDAPChannelBinding = ntlmIntPtr(2)
	}))
	if f.Count != 1 {
		t.Fatalf("measured + signing not required must fire, count=%d", f.Count)
	}
}

func TestNtlmRelayOpportunity_MeasuredChannelBindingNotRequiredFires(t *testing.T) {
	f := detectNtlmRelay(t, measuredNtlmData(func(rs *audit.RegistrySettings) {
		rs.LDAPServerIntegrity = ntlmIntPtr(2)
		rs.LDAPChannelBinding = ntlmIntPtr(0)
	}))
	if f.Count != 1 {
		t.Fatalf("measured + channel binding not required must fire, count=%d", f.Count)
	}
}
