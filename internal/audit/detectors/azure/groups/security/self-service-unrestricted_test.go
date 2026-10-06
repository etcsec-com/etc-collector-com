package security

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Reproduces the always-on false positive: GetTenantConfig never assigned
// GroupCreationPolicy, so it was always "" in production, and the detector
// treated "" (unknown) as "unrestricted". The detector must NOT treat an
// unknown/unassigned policy as unrestricted.
func TestSelfServiceUnrestricted_UnknownPolicyDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{AzureTenantConfig: &types.AzureTenantConfig{GroupCreationPolicy: ""}}
	f := NewSelfServiceUnrestrictedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for unknown/empty GroupCreationPolicy, got %d (false positive)", f.Count)
	}
}

func TestSelfServiceUnrestricted_ExplicitlyUnrestrictedFires(t *testing.T) {
	data := &audit.DetectorData{AzureTenantConfig: &types.AzureTenantConfig{GroupCreationPolicy: "unrestricted"}}
	f := NewSelfServiceUnrestrictedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 for explicitly unrestricted policy, got %d", f.Count)
	}
}

func TestSelfServiceUnrestricted_ExplicitlyRestrictedDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{AzureTenantConfig: &types.AzureTenantConfig{GroupCreationPolicy: "restricted"}}
	f := NewSelfServiceUnrestrictedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for restricted policy, got %d", f.Count)
	}
}
