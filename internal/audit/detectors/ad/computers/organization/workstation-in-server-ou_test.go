package organization

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestWorkstationInServerOu_ProductionWorkstationOUNotFlagged pins the fix:
// the old "ou=production" pattern matched ANY OU containing "production",
// including a legitimate "OU=Production-Workstations" - misclassifying
// that OU itself as a server OU and flagging every workstation in it. This
// is a heuristic detector with no vendor/regulatory referential (an OU
// naming scheme is site-specific), so the fix is precision, not a cited
// source.
func TestWorkstationInServerOu_ProductionWorkstationOUNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:              "CN=WKS01,OU=Production-Workstations,DC=contoso,DC=com",
				SAMAccountName:  "WKS01$",
				OperatingSystem: "Windows 11 Enterprise",
			},
		},
	}

	findings := NewWorkstationInServerOuDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: \"Production-Workstations\" is not a server OU", findings[0].Count)
	}
}

// TestWorkstationInServerOu_DisabledComputerNotFlagged pins the second
// fix: a decommissioned (disabled) computer's OU placement is not an
// active organizational risk.
func TestWorkstationInServerOu_DisabledComputerNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:              "CN=OLDPC,OU=Servers,DC=contoso,DC=com",
				SAMAccountName:  "OLDPC$",
				OperatingSystem: "Windows 10 Enterprise",
				Disabled:        true,
			},
		},
	}

	findings := NewWorkstationInServerOuDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a disabled computer must not be flagged", findings[0].Count)
	}
}

// TestWorkstationInServerOu_RealServerOUStillFlagged guards the surviving
// positive case: an enabled workstation genuinely misplaced in a server OU
// still fires.
func TestWorkstationInServerOu_RealServerOUStillFlagged(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{
				DN:              "CN=WKS02,OU=Servers,DC=contoso,DC=com",
				SAMAccountName:  "WKS02$",
				OperatingSystem: "Windows 11 Enterprise",
			},
		},
	}

	findings := NewWorkstationInServerOuDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: an enabled workstation in OU=Servers must still fire", findings[0].Count)
	}
}
