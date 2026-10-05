package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestPA038PointAndPrint_UnconfiguredNotFlagged is a red->green
// test: before the fix, a nil PointAndPrintNoElevation (no GPO override at
// all) was treated as vulnerable. Per Microsoft KB5005010, the OS itself has
// required elevation by default since the August 10, 2021 cumulative
// updates - nil now means "relying on the secure shipped default", not
// "vulnerable", and must not be flagged.
func TestPA038PointAndPrint_UnconfiguredNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{gpo}": {RegistrySettings: &audit.RegistrySettings{}},
		},
	}
	f := NewPA038PointAndPrintDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("PA038_POINT_AND_PRINT_ELEVATION_OFF: expected count=0 when unconfigured (secure-by-default post KB5005010), got %d", f.Count)
	}
}

// TestPA038PointAndPrint_ExplicitlyDisabled_StillFlagged confirms a GPO that
// explicitly sets the insecure value (1) is still flagged.
func TestPA038PointAndPrint_ExplicitlyDisabled_StillFlagged(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{gpo}": {RegistrySettings: &audit.RegistrySettings{PointAndPrintNoElevation: intPtr(1)}},
		},
	}
	f := NewPA038PointAndPrintDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("PA038_POINT_AND_PRINT_ELEVATION_OFF: expected count=1 when GPO explicitly disables elevation, got %d", f.Count)
	}
}

// TestPA038PointAndPrint_ExplicitlyEnabled_NotFlagged confirms a GPO that
// explicitly requires elevation (0) is not flagged.
func TestPA038PointAndPrint_ExplicitlyEnabled_NotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{gpo}": {RegistrySettings: &audit.RegistrySettings{PointAndPrintNoElevation: intPtr(0)}},
		},
	}
	f := NewPA038PointAndPrintDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("PA038_POINT_AND_PRINT_ELEVATION_OFF: expected count=0 when GPO explicitly requires elevation, got %d", f.Count)
	}
}
