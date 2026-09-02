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

// --- BP-039 R5 VBS ---

func TestBP039_VBS_Off_Triggers(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{})}
	if f := runPhaseB(t, NewBP039VBSOffDetector(), data); f == nil {
		t.Fatalf("VBS off should trigger")
	}
}

func TestBP039_VBS_Enabled_NoFinding(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{CredentialGuardEnabled: intp(1)})}
	if f := runPhaseB(t, NewBP039VBSOffDetector(), data); f != nil {
		t.Fatalf("VBS enabled should not trigger, got %+v", f)
	}
}

// --- BP-039 R8 HVCI ---

func TestBP039_HVCI_Off_Triggers(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{})}
	if f := runPhaseB(t, NewBP039HVCIOffDetector(), data); f == nil {
		t.Fatalf("HVCI off should trigger")
	}
}

func TestBP039_HVCI_Enabled_NoFinding(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{HVCIEnabled: intp(2)})}
	if f := runPhaseB(t, NewBP039HVCIOffDetector(), data); f != nil {
		t.Fatalf("HVCI enabled should not trigger")
	}
}

// --- BP-039 R9 HVCI without UEFI lock ---

func TestBP039_HVCI_NoLock_Triggers(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{HVCIEnabled: intp(1)})}
	if f := runPhaseB(t, NewBP039HVCINoUEFILockDetector(), data); f == nil {
		t.Fatalf("HVCI=1 should trigger no-UEFI-lock finding")
	}
}

func TestBP039_HVCI_WithLock_NoFinding(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{HVCIEnabled: intp(2)})}
	if f := runPhaseB(t, NewBP039HVCINoUEFILockDetector(), data); f != nil {
		t.Fatalf("HVCI=2 should not trigger")
	}
}

// --- BP-039 R14 Credential Guard without UEFI lock ---

func TestBP039_CredGuard_NoUEFILock_Triggers(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{LsaCfgFlags: intp(1)})}
	if f := runPhaseB(t, NewBP039CredGuardNoUEFILockDetector(), data); f == nil {
		t.Fatalf("LsaCfgFlags=1 should trigger no-lock finding")
	}
}

func TestBP039_CredGuard_WithUEFILock_NoFinding(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{LsaCfgFlags: intp(2)})}
	if f := runPhaseB(t, NewBP039CredGuardNoUEFILockDetector(), data); f != nil {
		t.Fatalf("LsaCfgFlags=2 should not trigger")
	}
}

// --- BP-039 R6/R7 CCI not deployed ---

func TestBP039_CCI_Empty_Triggers(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{})}
	if f := runPhaseB(t, NewBP039CCINotDeployedDetector(), data); f == nil {
		t.Fatalf("No CCI policy should trigger")
	}
}

func TestBP039_CCI_Deployed_NoFinding(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{DeviceGuardConfigCIPolicyFilePath: strp("\\\\domain\\policy.cip")})}
	if f := runPhaseB(t, NewBP039CCINotDeployedDetector(), data); f != nil {
		t.Fatalf("CCI deployed should not trigger")
	}
}

// --- BP-039 R13 Cached creds ---

func TestBP039_PrivCached_DefaultTriggers(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{})}
	if f := runPhaseB(t, NewBP039PrivAccountsCachedDetector(), data); f == nil {
		t.Fatalf("No cached count GPO should trigger (Win default = 10)")
	}
}

func TestBP039_PrivCached_Zeroed_NoFinding(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{CachedLogonsCount: intp(0)})}
	if f := runPhaseB(t, NewBP039PrivAccountsCachedDetector(), data); f != nil {
		t.Fatalf("Cache zeroed should not trigger")
	}
}

// --- R31 script secrets (v3.1.18 — uses dedicated script_secret type) ---

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
	// cpassword belongs to R32, not R31 — should not trigger here.
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

func TestR73_NTLMOutboundDenied_NoFinding(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{RestrictSendingNTLMTraffic: intp(2)})}
	if f := runPhaseB(t, NewR73NTLMOutboundTier0Detector(), data); f != nil {
		t.Fatalf("R73 deny should not trigger")
	}
}

func TestR74_OnlyOneGPO_Triggers(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{RestrictSendingNTLMTraffic: intp(2)})}
	if f := runPhaseB(t, NewR74NTLMOutboundDomainDetector(), data); f == nil {
		t.Fatalf("R74+ single GPO should trigger (suggests scoped)")
	}
}

// --- M29 local admin (v3.1.18 — real Restricted Groups parser) ---

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

// v3.1.18 — explicit empty MembersSIDs (admins drained) is also valid:
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
