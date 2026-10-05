package anssi

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// --- BP-039 R9 HVCI without UEFI lock ---
//
// HVCIEnabled=1 means "enabled WITH UEFI lock" and =2 means "enabled
// WITHOUT UEFI lock" per Microsoft's HypervisorEnforcedCodeIntegrity
// registry documentation - the opposite of what these tests (and the
// detector) previously assumed. The two cases below are swapped from the
// pre-fix version to match reality.

func TestBP039_HVCI_NoLock_Triggers(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{HVCIEnabled: intp(2)})}
	if f := runPhaseB(t, NewBP039HVCINoUEFILockDetector(), data); f == nil {
		t.Fatalf("HVCI=2 (enabled without UEFI lock) should trigger no-UEFI-lock finding")
	}
}

func TestBP039_HVCI_WithLock_NoFinding(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{HVCIEnabled: intp(1)})}
	if f := runPhaseB(t, NewBP039HVCINoUEFILockDetector(), data); f != nil {
		t.Fatalf("HVCI=1 (enabled with UEFI lock) should not trigger, got %+v", f)
	}
}
