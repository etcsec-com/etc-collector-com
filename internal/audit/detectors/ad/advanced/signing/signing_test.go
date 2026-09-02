package signing

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// T_046 / B_049 — when SYSVOL is unreachable (port 445 filtered, host down,
// ...), data.GPOPolicies is empty. The three detectors here used to read
// that as "no GPO configures this setting" and fire a Critical/High finding
// — i.e. they punished exactly the clients whose firewall filters 445, the
// ones who hardened their network. They must now distinguish "measured,
// setting absent" from "not measurable" and only fire in the first case.

func intPtr(v int) *int { return &v }

// unreachableData simulates SYSVOL never having been reached: no GPO
// policies were parsed at all (the same state as a real audit against a
// domain filtering 445).
func unreachableData() *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: "DC=example,DC=com", DomainName: "example"},
	}
}

// measuredData simulates a reachable SYSVOL with one parsed policy (the
// Default Domain Controllers Policy), whose RegistrySettings is set by the
// caller via the mutator.
func measuredData(mutate func(*audit.RegistrySettings)) *audit.DetectorData {
	rs := &audit.RegistrySettings{}
	if mutate != nil {
		mutate(rs)
	}
	return &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: "DC=example,DC=com", DomainName: "example"},
		GPOPolicies: map[string]*audit.GPOPolicy{
			helpers.DefaultDCPolicyGUID: {GUID: helpers.DefaultDCPolicyGUID, RegistrySettings: rs},
		},
	}
}

func detectSigning(t *testing.T, d audit.Detector, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("%s: expected exactly 1 finding, got %d", d.ID(), len(findings))
	}
	return findings[0]
}

// --- SMB_SIGNING_DISABLED ---

func TestSmbSigningDisabled_UnreachableSYSVOLDoesNotFire(t *testing.T) {
	f := detectSigning(t, NewSmbSigningDisabledDetector(), unreachableData())
	if f.Count != 0 {
		t.Fatalf("SYSVOL unreachable must not be reported as a finding, count=%d", f.Count)
	}
	if len(f.AffectedEntities) != 0 {
		t.Errorf("no entities should be attached when nothing was measured, got %+v", f.AffectedEntities)
	}
}

func TestSmbSigningDisabled_MeasuredAndInsecureFires(t *testing.T) {
	f := detectSigning(t, NewSmbSigningDisabledDetector(), measuredData(func(rs *audit.RegistrySettings) {
		rs.RequireSMBSigningServer = intPtr(0)
	}))
	if f.Count != 1 {
		t.Fatalf("measured + not required must fire, count=%d", f.Count)
	}
}

func TestSmbSigningDisabled_MeasuredNoPolicyKeyStillFires(t *testing.T) {
	// SYSVOL reachable, GPOs parsed, but none of them set this specific key —
	// Windows default (not required) genuinely applies. This is the "measured,
	// absent" case, distinct from "not measurable".
	f := detectSigning(t, NewSmbSigningDisabledDetector(), measuredData(nil))
	if f.Count != 1 {
		t.Fatalf("measured + key absent from every policy must still fire (Windows default), count=%d", f.Count)
	}
}

func TestSmbSigningDisabled_MeasuredAndSecureDoesNotFire(t *testing.T) {
	f := detectSigning(t, NewSmbSigningDisabledDetector(), measuredData(func(rs *audit.RegistrySettings) {
		rs.RequireSMBSigningServer = intPtr(1)
	}))
	if f.Count != 0 {
		t.Fatalf("measured + required must not fire, count=%d", f.Count)
	}
}

// --- LDAP_SIGNING_DISABLED ---

func TestLdapSigningDisabled_UnreachableSYSVOLDoesNotFire(t *testing.T) {
	f := detectSigning(t, NewLdapSigningDisabledDetector(), unreachableData())
	if f.Count != 0 {
		t.Fatalf("SYSVOL unreachable must not be reported as a finding, count=%d", f.Count)
	}
}

func TestLdapSigningDisabled_MeasuredAndInsecureFires(t *testing.T) {
	f := detectSigning(t, NewLdapSigningDisabledDetector(), measuredData(func(rs *audit.RegistrySettings) {
		rs.LDAPServerIntegrity = intPtr(1) // negotiate, not require
	}))
	if f.Count != 1 {
		t.Fatalf("measured + not required must fire, count=%d", f.Count)
	}
}

func TestLdapSigningDisabled_MeasuredNoPolicyKeyStillFires(t *testing.T) {
	f := detectSigning(t, NewLdapSigningDisabledDetector(), measuredData(nil))
	if f.Count != 1 {
		t.Fatalf("measured + key absent from every policy must still fire (Windows default), count=%d", f.Count)
	}
}

func TestLdapSigningDisabled_MeasuredAndSecureDoesNotFire(t *testing.T) {
	f := detectSigning(t, NewLdapSigningDisabledDetector(), measuredData(func(rs *audit.RegistrySettings) {
		rs.LDAPServerIntegrity = intPtr(2)
	}))
	if f.Count != 0 {
		t.Fatalf("measured + required must not fire, count=%d", f.Count)
	}
}

// --- LDAP_CHANNEL_BINDING_DISABLED ---

func TestLdapChannelBindingDisabled_UnreachableSYSVOLDoesNotFire(t *testing.T) {
	f := detectSigning(t, NewLdapChannelBindingDisabledDetector(), unreachableData())
	if f.Count != 0 {
		t.Fatalf("SYSVOL unreachable must not be reported as a finding, count=%d", f.Count)
	}
}

func TestLdapChannelBindingDisabled_MeasuredAndInsecureFires(t *testing.T) {
	f := detectSigning(t, NewLdapChannelBindingDisabledDetector(), measuredData(func(rs *audit.RegistrySettings) {
		rs.LDAPChannelBinding = intPtr(1) // when supported, not always
	}))
	if f.Count != 1 {
		t.Fatalf("measured + not always must fire, count=%d", f.Count)
	}
}

func TestLdapChannelBindingDisabled_MeasuredNoPolicyKeyStillFires(t *testing.T) {
	f := detectSigning(t, NewLdapChannelBindingDisabledDetector(), measuredData(nil))
	if f.Count != 1 {
		t.Fatalf("measured + key absent from every policy must still fire (Windows default), count=%d", f.Count)
	}
}

func TestLdapChannelBindingDisabled_MeasuredAndSecureDoesNotFire(t *testing.T) {
	f := detectSigning(t, NewLdapChannelBindingDisabledDetector(), measuredData(func(rs *audit.RegistrySettings) {
		rs.LDAPChannelBinding = intPtr(2)
	}))
	if f.Count != 0 {
		t.Fatalf("measured + always must not fire, count=%d", f.Count)
	}
}
