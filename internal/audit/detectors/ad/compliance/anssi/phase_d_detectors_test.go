package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R59 ---

func r59BaseData(domainDN string, tier0OU types.OU, gpoDN, gpoGUID string) *audit.DetectorData {
	return &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: domainDN},
		OUs:        []types.OU{tier0OU},
		GPOs:       []types.GPO{{DN: gpoDN, GUID: gpoGUID}},
	}
}

func TestR59Tier0OUPolicies_Detect(t *testing.T) {
	domainDN := "DC=test,DC=local"
	tier0OU := types.OU{DN: "OU=Tier0," + domainDN}
	gpoGUID := "aaaaaaaa-1111-2222-3333-444444444444"
	gpoDN := "CN={" + gpoGUID + "},CN=Policies,CN=System," + domainDN

	t.Run("weak-ACL GPO linked to Tier0 OU -> flagged", func(t *testing.T) {
		data := r59BaseData(domainDN, tier0OU, gpoDN, gpoGUID)
		data.GPOAcls = []audit.GPOAcl{
			{GPODN: gpoDN, Trustee: "S-1-5-21-1-2-3-1105", AccessMask: types.MaskWriteDACL, AceType: "ACCESS_ALLOWED"},
		}
		data.GPOLinks = []audit.GPOLink{
			{GPOCN: gpoGUID, LinkedTo: tier0OU.DN, LinkEnabled: true},
		}
		d := NewR59Tier0OUPoliciesDetector()
		findings := d.Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count == 0 {
			t.Fatalf("expected a flagged finding, got %+v", findings)
		}
	})

	t.Run("GPO linked but ACL not weak -> clean", func(t *testing.T) {
		data := r59BaseData(domainDN, tier0OU, gpoDN, gpoGUID)
		data.GPOLinks = []audit.GPOLink{
			{GPOCN: gpoGUID, LinkedTo: tier0OU.DN, LinkEnabled: true},
		}
		d := NewR59Tier0OUPoliciesDetector()
		findings := d.Detect(context.Background(), data)
		if len(findings) != 0 {
			t.Fatalf("expected no finding, got %+v", findings)
		}
	})

	t.Run("weak-ACL GPO linked elsewhere, not to Tier0 OU -> clean", func(t *testing.T) {
		data := r59BaseData(domainDN, tier0OU, gpoDN, gpoGUID)
		data.GPOAcls = []audit.GPOAcl{
			{GPODN: gpoDN, Trustee: "S-1-5-21-1-2-3-1105", AccessMask: types.MaskWriteDACL, AceType: "ACCESS_ALLOWED"},
		}
		data.GPOLinks = []audit.GPOLink{
			{GPOCN: gpoGUID, LinkedTo: "OU=Sales," + domainDN, LinkEnabled: true},
		}
		d := NewR59Tier0OUPoliciesDetector()
		findings := d.Detect(context.Background(), data)
		if len(findings) != 0 {
			t.Fatalf("expected no finding, got %+v", findings)
		}
	})

	t.Run("no Tier0 OU present -> no finding, nothing to evaluate", func(t *testing.T) {
		data := &audit.DetectorData{DomainInfo: &types.DomainInfo{DomainDN: domainDN}}
		d := NewR59Tier0OUPoliciesDetector()
		findings := d.Detect(context.Background(), data)
		if len(findings) != 0 {
			t.Fatalf("expected no finding, got %+v", findings)
		}
	})
}

// the finding used to claim full R59 coverage. It only checks one
// of R59's three components (weak-ACL GPOs linked to the Tier 0 OU); it
// can't verify inheritance blocking (data not collected) or the Default
// Domain Policy priority requirement. The description must say so.
func TestR59Tier0OUPolicies_ScopeHonestlyAnnounced(t *testing.T) {
	domainDN := "DC=test,DC=local"
	tier0OU := types.OU{DN: "OU=Tier0," + domainDN}
	gpoGUID := "bbbbbbbb-1111-2222-3333-444444444444"
	gpoDN := "CN={" + gpoGUID + "},CN=Policies,CN=System," + domainDN
	data := r59BaseData(domainDN, tier0OU, gpoDN, gpoGUID)
	data.GPOAcls = []audit.GPOAcl{
		{GPODN: gpoDN, Trustee: "S-1-5-21-1-2-3-1105", AccessMask: types.MaskWriteDACL, AceType: "ACCESS_ALLOWED"},
	}
	data.GPOLinks = []audit.GPOLink{
		{GPOCN: gpoGUID, LinkedTo: tier0OU.DN, LinkEnabled: true},
	}
	d := NewR59Tier0OUPoliciesDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	desc := strings.ToLower(findings[0].Description)
	if !strings.Contains(desc, "does not verify") && !strings.Contains(desc, "does not observe") {
		t.Errorf("description should honestly disclose uncovered R59 scope, got %q", findings[0].Description)
	}
}

// --- R79 relabeling + no-data false positive ---

// TestR79RDPHardened_NoDataAtAll_NoFalsePositive: with no
// GPOPolicies at all (SMB/SYSVOL not collected), both the highEnc and rpcEnc
// signals default to false, and the detector used to report a guaranteed
// "not hardened" finding indistinguishable from a real violation. Absence of
// evidence must not be reported as a violation (same principle as the R4/R13
// no-data fix in r4-logging.go).
func TestR79RDPHardened_NoDataAtAll_NoFalsePositive(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: nil}
	d := NewR79RDPHardenedDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding when no GPO data was collected at all, got %+v", findings)
	}
}

// TestR79RDPHardened_WeakSettingsPresent_StillFlagged is the regression
// check: when GPO data IS present and genuinely doesn't set the required
// encryption, the finding must still fire.
func TestR79RDPHardened_WeakSettingsPresent_StillFlagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {RegistrySettings: &audit.RegistrySettings{}},
	}}
	d := NewR79RDPHardenedDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count == 0 {
		t.Fatalf("expected a flagged finding, got %+v", findings)
	}
}

// TestR79RDPHardened_DoesNotClaimANSSIR79: this detector checks
// server-side RDP encryption (MinEncryptionLevel/fEncryptRPCTraffic), but
// ANSSI R79 (p.104-105) is about hardening the RDP CLIENT (graphics
// acceleration, clipboard/smart-card redirection) - an entirely different,
// uncollected set of settings. The finding must not attribute this check to
// R79.
func TestR79RDPHardened_DoesNotClaimANSSIR79(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {RegistrySettings: &audit.RegistrySettings{}},
	}}
	d := NewR79RDPHardenedDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	title := findings[0].Title
	if strings.Contains(title, "R79") {
		t.Errorf("title still attributes this check to ANSSI R79: %q", title)
	}
	if !strings.Contains(findings[0].Description, "NOT a measurement of ANSSI R79") {
		t.Errorf("description should explicitly disclaim R79 attribution, got %q", findings[0].Description)
	}
}

// --- R86 name-heuristic false positives ---

// TestR86AdminForestSegregation_BareSubstringsNoLongerMatch:
// adminForestNameMarkers used to include bare "red" and "t0", which match
// common unrelated substrings ("shared", "credentials" contain "red";
// "test01" contains "t0" via "st0"). Neither of these domains is an admin
// forest and neither should be flagged after the fix.
func TestR86AdminForestSegregation_BareSubstringsNoLongerMatch(t *testing.T) {
	falsePositiveDomains := []string{"shared.corp.local", "credentials.corp.local", "test01.corp.local"}
	for _, domain := range falsePositiveDomains {
		t.Run(domain, func(t *testing.T) {
			data := &audit.DetectorData{
				Trusts: []types.Trust{{TargetDomain: domain, SIDFiltering: false, SelectiveAuth: false}},
			}
			d := NewR86AdminForestSegregationDetector()
			findings := d.Detect(context.Background(), data)
			if len(findings) != 0 {
				t.Errorf("domain %q should no longer match the admin-forest heuristic, got %+v", domain, findings)
			}
		})
	}
}

// TestR86AdminForestSegregation_RealMarkerStillMatches is the regression
// check: a genuine admin-forest-looking trust name must still be flagged
// when weakly configured.
func TestR86AdminForestSegregation_RealMarkerStillMatches(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{{TargetDomain: "tier0.corp.local", SIDFiltering: false, SelectiveAuth: false}},
	}
	d := NewR86AdminForestSegregationDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count == 0 {
		t.Fatalf("expected a flagged finding for a genuine tier0-named trust, got %+v", findings)
	}
}

// --- R82/R83 relabeling ---

func denyRightsPolicy(sids ...string) map[string]*audit.GPOPolicy {
	return map[string]*audit.GPOPolicy{
		"policy-1": {
			PrivilegeRights: &audit.PrivilegeRights{
				SeDenyNetworkLogonRight:           sids,
				SeDenyInteractiveLogonRight:       sids,
				SeDenyRemoteInteractiveLogonRight: sids,
			},
		},
	}
}

func TestR82R83AdminArchitecture_Detect(t *testing.T) {
	cases := []struct {
		name     string
		policies map[string]*audit.GPOPolicy
		wantFlag bool
	}{
		{"deny rights configured for Authenticated Users -> clean", denyRightsPolicy("S-1-5-11"), false},
		{"no GPO configures deny rights -> flagged", nil, true},
		{"deny rights configured for an unrelated SID only -> flagged", denyRightsPolicy("S-1-5-32-544"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{GPOPolicies: tc.policies}
			d := NewR82R83AdminArchitectureDetector()
			findings := d.Detect(context.Background(), data)
			flagged := len(findings) == 1 && findings[0].Count > 0
			if flagged != tc.wantFlag {
				t.Errorf("flagged = %v, want %v (findings=%+v)", flagged, tc.wantFlag, findings)
			}
		})
	}
}

// this finding used to claim it measures ANSSI R82 + R83. Both are
// about restricting Tier 0's OUTBOUND connections to less-trusted zones
// (the opposite direction of a deny-inbound-logon GPO check), and the
// guide's own footnote on R83 says deny-logon GPO settings alone don't
// satisfy it. The finding must no longer attribute this check to R82/R83.
func TestR82R83AdminArchitecture_DoesNotClaimANSSIR82R83(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: nil}
	d := NewR82R83AdminArchitectureDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count == 0 {
		t.Fatalf("expected a flagged finding, got %+v", findings)
	}
	title, desc := findings[0].Title, findings[0].Description
	if strings.Contains(title, "R82") || strings.Contains(title, "R83") {
		t.Errorf("title still attributes this check to R82/R83: %q", title)
	}
	if !strings.Contains(desc, "NOT a measurement of ANSSI R82 or R83") {
		t.Errorf("description should explicitly disclaim R82/R83 attribution, got %q", desc)
	}
}
