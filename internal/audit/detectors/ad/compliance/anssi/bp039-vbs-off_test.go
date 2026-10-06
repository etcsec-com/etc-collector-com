package anssi

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

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
