package anssi

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// gpoWith returns a single-policy map suitable for DetectorData.GPOPolicies.
// One-liner factory used by Phase C tests.
func gpoWith(rs *audit.RegistrySettings) map[string]*audit.GPOPolicy {
	return map[string]*audit.GPOPolicy{
		"GUID-1": {GUID: "GUID-1", DisplayName: "Test GPO", RegistrySettings: rs},
	}
}

func intp(v int) *int       { return &v }
func strp(v string) *string { return &v }

// --- R31 script secrets (v3.1.18 - uses dedicated script_secret type) ---

func TestR31_PowerShellSecret_Triggers(t *testing.T) {
	data := &audit.DetectorData{
		SYSVOLFindings: []audit.SYSVOLFinding{
			{Type: "script_secret", FilePath: "\\\\domain\\sysvol\\Scripts\\setup.ps1", Details: "PowerShell ConvertTo-SecureString -AsPlainText -Force"},
		},
		IncludeDetails: true,
	}
	if f := runPhaseB(t, NewR31ScriptSecretsDetector(), data); f == nil || f.Count != 1 {
		t.Fatalf("R31 script_secret should trigger, got %+v", f)
	}
}

func TestR31_GPPCpassword_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		SYSVOLFindings: []audit.SYSVOLFinding{
			{Type: "cpassword", FilePath: "\\\\domain\\sysvol\\Groups.xml", Details: "cpassword=..."},
		},
	}
	// cpassword belongs to R32, not R31 - should not trigger here.
	if f := runPhaseB(t, NewR31ScriptSecretsDetector(), data); f != nil {
		t.Fatalf("R31 should not pick up cpassword, got %+v", f)
	}
}

// --- R37 weak cert templates ---

func TestR37_ESC1_Triggers(t *testing.T) {
	data := &audit.DetectorData{
		CertTemplates: []types.CertTemplate{{
			DN:                  "CN=ESC1,...",
			DisplayName:         "ESC1Template",
			ExtendedKeyUsage:    []string{"1.3.6.1.5.5.7.3.2"}, // Client Auth
			CertificateNameFlag: 0x1,                           // EnrolleeSuppliesSubject
		}},
		IncludeDetails: true,
	}
	if f := runPhaseB(t, NewR37WeakCertTemplatesDetector(), data); f == nil || f.Count != 1 {
		t.Fatalf("R37 ESC1 should trigger, got %+v", f)
	}
}

func TestR37_HardenedTemplate_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		CertTemplates: []types.CertTemplate{{
			DN:                      "CN=Hard,...",
			DisplayName:             "HardenedTemplate",
			ExtendedKeyUsage:        []string{"1.3.6.1.5.5.7.3.2"},
			CertificateNameFlag:     0, // no EnrolleeSuppliesSubject
			RequiresManagerApproval: true,
		}},
	}
	if f := runPhaseB(t, NewR37WeakCertTemplatesDetector(), data); f != nil {
		t.Fatalf("R37 hardened template should not trigger")
	}
}

// --- R73 / R74 NTLM outbound ---

func TestR73_NTLMOutboundNotDenied_Triggers(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{RestrictSendingNTLMTraffic: intp(1)})} // audit-only
	if f := runPhaseB(t, NewR73NTLMOutboundTier0Detector(), data); f == nil {
		t.Fatalf("R73 audit-only should trigger (need Deny)")
	}
}

// R73 requires the setting to actually APPLY to Tier 0, not merely to exist
// somewhere in the domain. A GPO that denies outbound NTLM but is linked
// nowhere near Tier 0 leaves Tier 0 unprotected, so the deny alone is not
// compliance - that gap used to read as compliant.
func TestR73_NTLMOutboundDenied_LinkedAtDomainRoot_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: gpoWith(&audit.RegistrySettings{RestrictSendingNTLMTraffic: intp(2)}),
		DomainInfo:  &types.DomainInfo{DomainDN: "DC=example,DC=com"},
		GPOLinks: []audit.GPOLink{{
			GPOCN: "GUID-1", LinkedTo: "DC=example,DC=com", LinkEnabled: true,
		}},
	}
	if f := runPhaseB(t, NewR73NTLMOutboundTier0Detector(), data); f != nil {
		t.Fatalf("R73 deny linked at the domain root covers Tier 0 and should not trigger")
	}
}

func TestR73_NTLMOutboundDenied_NotLinkedToTier0_Triggers(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: gpoWith(&audit.RegistrySettings{RestrictSendingNTLMTraffic: intp(2)}),
		DomainInfo:  &types.DomainInfo{DomainDN: "DC=example,DC=com"},
		GPOLinks: []audit.GPOLink{{
			GPOCN: "GUID-1", LinkedTo: "OU=Workstations,DC=example,DC=com", LinkEnabled: true,
		}},
	}
	if f := runPhaseB(t, NewR73NTLMOutboundTier0Detector(), data); f == nil {
		t.Fatalf("R73 deny linked only to an unrelated OU leaves Tier 0 uncovered and must trigger")
	}
}

func TestR74_OnlyOneGPO_Triggers(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{RestrictSendingNTLMTraffic: intp(2)})}
	if f := runPhaseB(t, NewR74NTLMOutboundDomainDetector(), data); f == nil {
		t.Fatalf("R74+ single GPO should trigger (suggests scoped)")
	}
}

// --- M29 local admin (v3.1.18 - real Restricted Groups parser) ---

func TestM29_NoRestrictedGroupGPO_Triggers(t *testing.T) {
	// Two GPOs parsed but neither has a [Group Membership] entry for
	// BUILTIN\Administrators → M29 fires.
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"GUID-1": {GUID: "GUID-1", DisplayName: "Default Domain Policy"},
			"GUID-2": {GUID: "GUID-2", DisplayName: "Audit Settings"},
		},
	}
	if f := runPhaseB(t, NewM29LocalAdminNotRestrictedDetector(), data); f == nil {
		t.Fatalf("M29 no restricted GPO should trigger")
	}
}

func TestM29_RestrictedGroupGPO_NoFinding(t *testing.T) {
	// One GPO restricts BUILTIN\Administrators (S-1-5-32-544) to a specific
	// set of SIDs → M29 met.
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"GUID-1": {
				GUID:        "GUID-1",
				DisplayName: "Workstation Hardening",
				RestrictedGroups: []audit.RestrictedGroupSpec{
					{
						GroupSID:    "S-1-5-32-544",
						GroupName:   "BUILTIN\\Administrators",
						MembersSIDs: []string{"S-1-5-21-DOMAIN-512", "S-1-5-21-DOMAIN-WS-ADMINS"},
					},
				},
			},
		},
	}
	if f := runPhaseB(t, NewM29LocalAdminNotRestrictedDetector(), data); f != nil {
		t.Fatalf("M29 restricted GPO present should not trigger, got %+v", f)
	}
}

// v3.1.18 - explicit empty MembersSIDs (admins drained) is also valid:
// BUILTIN\Administrators with zero members = "no local admins on this host",
// which is the most restrictive valid policy.
func TestM29_EmptyAdminsSet_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"GUID-1": {
				GUID: "GUID-1",
				RestrictedGroups: []audit.RestrictedGroupSpec{
					{GroupSID: "S-1-5-32-544", MembersSIDs: []string{}}, // not nil
				},
			},
		},
	}
	if f := runPhaseB(t, NewM29LocalAdminNotRestrictedDetector(), data); f != nil {
		t.Fatalf("M29 empty admins set should be treated as restricted, got %+v", f)
	}
}
