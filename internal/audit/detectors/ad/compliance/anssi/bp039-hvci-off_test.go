package anssi

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

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
