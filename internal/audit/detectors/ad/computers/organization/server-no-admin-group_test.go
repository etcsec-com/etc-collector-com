package organization

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestServerNoAdminGroupDetector covers SERVER_NO_ADMIN_GROUP: the title
// promises "servers without a managed admin group" but the old code only
// matched a keyword ("unmanaged"/"legacy"/"deprecated") in the computer's
// Description field, never inspecting any actual admin-group management
// signal - Count stayed 0 on any domain with unset Description fields
// (most domains). Fixed to read the real signal: a GPO Restricted Groups /
// Group Policy Preferences setting (parsed from SYSVOL GptTmpl.inf,
// data.GPOPolicies) that pins local BUILTIN\Administrators to an explicit
// member set and is linked (enabled) to the server's OU.
func TestServerNoAdminGroupDetector(t *testing.T) {
	srv01DN := "CN=SRV01,OU=Servers,DC=contoso,DC=com"
	srv02DN := "CN=SRV02,OU=Servers,DC=contoso,DC=com"

	managingPolicy := func() *audit.GPOPolicy {
		return &audit.GPOPolicy{
			GUID: "{11111111-0000-0000-0000-000000000001}",
			RestrictedGroups: []audit.RestrictedGroupSpec{
				{GroupSID: builtinAdministratorsSID, MembersSIDs: []string{"S-1-5-21-1-2-3-5000"}},
			},
		}
	}

	t.Run("no GPOPolicies data at all -> skipped, not flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers:      []types.Computer{{DN: srv01DN, SAMAccountName: "SRV01$", Disabled: false}},
			IncludeDetails: true,
		}
		f := detectServerNoAdminGroup(t, data)
		if f.Count != 0 {
			t.Fatalf("without SYSVOL/GPO data the detector cannot tell managed from unmanaged, got Count=%d", f.Count)
		}
	})

	t.Run("server covered by a Restricted-Groups GPO linked to its OU -> not flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{{DN: srv01DN, SAMAccountName: "SRV01$", Disabled: false}},
			GPOPolicies: map[string]*audit.GPOPolicy{
				"{11111111-0000-0000-0000-000000000001}": managingPolicy(),
			},
			GPOLinks: []audit.GPOLink{
				{GPOCN: "{11111111-0000-0000-0000-000000000001}", LinkedTo: "OU=Servers,DC=contoso,DC=com", LinkEnabled: true},
			},
			IncludeDetails: true,
		}
		f := detectServerNoAdminGroup(t, data)
		if f.Count != 0 {
			t.Fatalf("server under an OU covered by a managing GPO must not be flagged, got Count=%d", f.Count)
		}
	})

	t.Run("server NOT covered by any managing GPO -> flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: srv01DN, SAMAccountName: "SRV01$", Disabled: false},
				{DN: srv02DN, SAMAccountName: "SRV02$", Disabled: false},
			},
			GPOPolicies: map[string]*audit.GPOPolicy{
				"{11111111-0000-0000-0000-000000000001}": managingPolicy(),
			},
			// Managing GPO exists but is linked to a DIFFERENT, unrelated OU.
			GPOLinks: []audit.GPOLink{
				{GPOCN: "{11111111-0000-0000-0000-000000000001}", LinkedTo: "OU=Marketing,DC=contoso,DC=com", LinkEnabled: true},
			},
			IncludeDetails: true,
		}
		f := detectServerNoAdminGroup(t, data)
		if f.Count != 2 {
			t.Fatalf("neither server is covered by the managing GPO's link, want Count=2, got %d", f.Count)
		}
	})

	t.Run("managing GPO's link is disabled -> server still flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{{DN: srv01DN, SAMAccountName: "SRV01$", Disabled: false}},
			GPOPolicies: map[string]*audit.GPOPolicy{
				"{11111111-0000-0000-0000-000000000001}": managingPolicy(),
			},
			GPOLinks: []audit.GPOLink{
				{GPOCN: "{11111111-0000-0000-0000-000000000001}", LinkedTo: "OU=Servers,DC=contoso,DC=com", LinkEnabled: false},
			},
			IncludeDetails: true,
		}
		f := detectServerNoAdminGroup(t, data)
		if f.Count != 1 {
			t.Fatalf("a disabled link does not apply the GPO, server must be flagged, got Count=%d", f.Count)
		}
	})

	t.Run("disabled computer account is never flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{{DN: srv01DN, SAMAccountName: "SRV01$", Disabled: true}},
			GPOPolicies: map[string]*audit.GPOPolicy{
				"{11111111-0000-0000-0000-000000000001}": managingPolicy(),
			},
			IncludeDetails: true,
		}
		f := detectServerNoAdminGroup(t, data)
		if f.Count != 0 {
			t.Fatalf("disabled computer accounts must not be flagged, got Count=%d", f.Count)
		}
	})

	t.Run("non-server computer is never flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{{DN: "CN=WS01,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "WS01$", Disabled: false, OperatingSystem: "Windows 11 Enterprise"}},
			GPOPolicies: map[string]*audit.GPOPolicy{
				"{11111111-0000-0000-0000-000000000001}": managingPolicy(),
			},
			IncludeDetails: true,
		}
		f := detectServerNoAdminGroup(t, data)
		if f.Count != 0 {
			t.Fatalf("a workstation must not be flagged by a server-scoped detector, got Count=%d", f.Count)
		}
	})
}

func detectServerNoAdminGroup(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewServerNoAdminGroupDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}
