package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func intPtr(v int) *int { return &v }

// TestPA038RDPNLA_UnreachableSYSVOLDoesNotFire covers a fail-open bug:
// PA038_RDP_NLA_NOT_REQUIRED fired unconditionally whenever SYSVOL was
// unreachable (data.GPOPolicies empty) - the same fail-open bug already
// fixed for SMB/LDAP signing elsewhere in this codebase. enforced starts false and the
// empty-map loop never flips it, so count=1 fired despite zero GPOs having
// been measured - "not measurable" was scored the same as "measured,
// absent".
func TestPA038RDPNLA_UnreachableSYSVOLDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: "DC=example,DC=com", DomainName: "example"},
	}
	f := NewPA038RDPNLADetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("PA038_RDP_NLA_NOT_REQUIRED: expected count=0 when SYSVOL unreachable (unmeasured), got %d", f.Count)
	}
}

// TestPA038RDPNLA_MeasuredNotEnforcedStillFires is a sanity check: once a
// GPO is actually parsed and does not set UserAuthentication=1, the
// detector must still fire (measured absence, not silence-by-default).
func TestPA038RDPNLA_MeasuredNotEnforcedStillFires(t *testing.T) {
	rs := &audit.RegistrySettings{}
	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: "DC=example,DC=com", DomainName: "example"},
		GPOPolicies: map[string]*audit.GPOPolicy{
			helpers.DefaultDCPolicyGUID: {GUID: helpers.DefaultDCPolicyGUID, RegistrySettings: rs},
		},
	}
	f := NewPA038RDPNLADetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("PA038_RDP_NLA_NOT_REQUIRED: expected count=1 when GPO measured and NLA not set, got %d", f.Count)
	}
}

// TestPA038RDPNLA_EnforcedDoesNotFire is a sanity check: a GPO that does
// set UserAuthentication=1 must clear the finding.
func TestPA038RDPNLA_EnforcedDoesNotFire(t *testing.T) {
	rs := &audit.RegistrySettings{RDPNLA: intPtr(1)}
	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: "DC=example,DC=com", DomainName: "example"},
		GPOPolicies: map[string]*audit.GPOPolicy{
			helpers.DefaultDCPolicyGUID: {GUID: helpers.DefaultDCPolicyGUID, RegistrySettings: rs},
		},
	}
	f := NewPA038RDPNLADetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("PA038_RDP_NLA_NOT_REQUIRED: expected count=0 when GPO enforces NLA, got %d", f.Count)
	}
}

// TestPA038RDPNLA_TitleReflectsGPOOnlyScope_CitesRealANSSIRule_SeverityMedium
// is a red->green test: before the fix, this cited a fabricated
// "ANSSI PA-038" document and claimed NLA was flatly "not required" (High)
// from GPO absence alone - but a host can have NLA enabled locally (the
// Windows Server default in RD Session Host Configuration / the Remote tab
// since Server 2012 R2, independent of any GPO) and still be counted
// vulnerable by this GPO-only check. Retitled to what is actually measured,
// retagged to the real ANSSI PA-099 R18 citation already used for this
// detector in compliance/mappings.go, and lowered to Medium to match the
// equivalent GPO-only measurement's severity elsewhere in this codebase
// (gpo.TerminalServicesNotHardenedDetector).
func TestPA038RDPNLA_TitleReflectsGPOOnlyScope_CitesRealANSSIRule_SeverityMedium(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{gpo}": {RegistrySettings: &audit.RegistrySettings{}},
		},
	}
	f := NewPA038RDPNLADetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityMedium {
		t.Errorf("PA038_RDP_NLA_NOT_REQUIRED: Severity = %q, want %q", f.Severity, types.SeverityMedium)
	}
	if strings.Contains(f.Title, "PA-038") || strings.Contains(f.Description, "ANSSI PA-038") {
		t.Errorf("PA038_RDP_NLA_NOT_REQUIRED still cites the fabricated ANSSI PA-038 reference: title=%q desc=%q", f.Title, f.Description)
	}
	if strings.Contains(f.Title, "non requis") {
		t.Errorf("PA038_RDP_NLA_NOT_REQUIRED title still claims NLA is flatly \"not required\" instead of \"not enforced via GPO\": title=%q", f.Title)
	}
	if !strings.Contains(f.Title, "GPO") {
		t.Errorf("PA038_RDP_NLA_NOT_REQUIRED title does not scope the claim to GPO enforcement: title=%q", f.Title)
	}
	if !strings.Contains(f.Description, "ANSSI PA-099") {
		t.Errorf("PA038_RDP_NLA_NOT_REQUIRED description does not cite the real ANSSI PA-099 R18 reference: desc=%q", f.Description)
	}
}

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
