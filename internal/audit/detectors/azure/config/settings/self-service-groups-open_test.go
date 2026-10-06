package settings

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestSelfServiceGroupsOpen_RestrictedTenant_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{GroupUnifiedCreationPolicy: "Restricted"},
	}
	f := NewSelfServiceGroupsOpenDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("tenant explicitly restricts group creation: expected Count 0, got %d", f.Count)
	}
}

func TestSelfServiceGroupsOpen_UnknownPolicy_NoFinding(t *testing.T) {
	// GroupUnifiedCreationPolicy == "" means the provider read failed/never
	// ran - must not be treated as "open".
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{GroupUnifiedCreationPolicy: ""},
	}
	f := NewSelfServiceGroupsOpenDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("unknown policy must not fire: expected Count 0, got %d", f.Count)
	}
}

func TestSelfServiceGroupsOpen_ConfirmedOpen_Fires(t *testing.T) {
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{GroupUnifiedCreationPolicy: "Open"},
	}
	f := NewSelfServiceGroupsOpenDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("confirmed open policy: expected Count 1, got %d", f.Count)
	}
}
