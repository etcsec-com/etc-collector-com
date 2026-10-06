package anssi

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// --- BP-039 R14 Credential Guard without UEFI lock ---
//
// Same inversion as HVCI above - LsaCfgFlags=1 is "with UEFI lock",
// =2 is "without lock" (Microsoft Credential Guard registry docs).

func TestBP039_CredGuard_NoUEFILock_Triggers(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{LsaCfgFlags: intp(2)})}
	if f := runPhaseB(t, NewBP039CredGuardNoUEFILockDetector(), data); f == nil {
		t.Fatalf("LsaCfgFlags=2 (no lock) should trigger no-lock finding")
	}
}

func TestBP039_CredGuard_WithUEFILock_NoFinding(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{LsaCfgFlags: intp(1)})}
	if f := runPhaseB(t, NewBP039CredGuardNoUEFILockDetector(), data); f != nil {
		t.Fatalf("LsaCfgFlags=1 (with UEFI lock) should not trigger, got %+v", f)
	}
}
