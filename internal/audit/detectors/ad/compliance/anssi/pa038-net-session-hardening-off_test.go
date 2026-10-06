package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestPA038NetSessionHardening_NoANSSICitation_AndSeverityInfo is a
// red->green test: before the fix, this cited a fabricated "ANSSI PA-038"
// document and fired at SeverityMedium. No ANSSI document covers NetCease;
// the check is also structurally blind to the real (REG_BINARY) mitigation,
// so it was lowered to Info.
func TestPA038NetSessionHardening_NoANSSICitation_AndSeverityInfo(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{gpo}": {RegistrySettings: &audit.RegistrySettings{}},
		},
	}
	f := NewPA038NetSessionHardeningDetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityInfo {
		t.Errorf("PA038_NET_SESSION_HARDENING_OFF: Severity = %q, want %q", f.Severity, types.SeverityInfo)
	}
	if strings.Contains(f.Title, "PA-038") || strings.Contains(f.Description, "ANSSI PA-038") {
		t.Errorf("PA038_NET_SESSION_HARDENING_OFF still cites the fabricated ANSSI PA-038 reference: title=%q desc=%q", f.Title, f.Description)
	}
}
