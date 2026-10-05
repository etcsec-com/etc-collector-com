package anssi

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

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

// TestBP039_CCI_VBSAloneDoesNotSilence: the detector used to
// treat DeviceGuardCodeIntegrityPolicyEnforcement>=1 (wired to
// DeviceGuard\RequirePlatformSecurityFeatures, the VBS "Select Platform
// Security Level" setting) as proof CCI/WDAC was deployed. VBS being on
// says nothing about whether a Code Integrity policy was ever deployed -
// this was a false "compliant" on a genuinely undeployed control. With no
// ConfigCIPolicyFilePath set, the finding must fire regardless of the VBS
// setting.
func TestBP039_CCI_VBSAloneDoesNotSilence(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{DeviceGuardCodeIntegrityPolicyEnforcement: intp(1)})}
	if f := runPhaseB(t, NewBP039CCINotDeployedDetector(), data); f == nil {
		t.Fatalf("VBS platform security level alone must not silence the CCI/WDAC-not-deployed finding")
	}
}
