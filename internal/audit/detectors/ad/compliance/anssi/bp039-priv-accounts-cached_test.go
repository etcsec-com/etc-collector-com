package anssi

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

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
