package status

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestAdminCount_ComputerWithAdminCountTrueFires(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WS-20,OU=Workstations,DC=contoso,DC=com", AdminCount: true},
		},
	}
	findings := NewAdminCountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("a computer with AdminCount=true must fire, got count=%d", findings[0].Count)
	}
}

func TestAdminCount_ComputerWithAdminCountFalseDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WS-21,OU=Workstations,DC=contoso,DC=com", AdminCount: false},
		},
	}
	findings := NewAdminCountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("a computer with AdminCount=false must not fire, got count=%d", findings[0].Count)
	}
}

// TestAdminCount_ExcludesDisabledComputers covers the guard added by the
// split: a disabled computer carrying the exact same AdminCount=true as a
// live true positive must not fire here anymore - it is reported instead,
// at Info, by AdminCountOnDisabledAccountDetector.
func TestAdminCount_ExcludesDisabledComputers(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WS-22,OU=Workstations,DC=contoso,DC=com", Disabled: true, AdminCount: true},
		},
	}
	findings := NewAdminCountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("a disabled computer with AdminCount=true must not fire in the active detector, got count=%d", findings[0].Count)
	}
}

func TestAdminCount_CountMatchesAffectedEntitiesLength(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=WS-23,OU=Workstations,DC=contoso,DC=com", AdminCount: true},
			{DN: "CN=WS-24,OU=Workstations,DC=contoso,DC=com", AdminCount: false},
			{DN: "CN=WS-25,OU=Workstations,DC=contoso,DC=com", AdminCount: true},
			{DN: "CN=WS-26,OU=Workstations,DC=contoso,DC=com", Disabled: true, AdminCount: true},
		},
	}
	findings := NewAdminCountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 2 {
		t.Fatalf("expected count=2 for a mixed list (disabled entry excluded), got %d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != findings[0].Count {
		t.Fatalf("AffectedEntities length %d must match Count %d", len(findings[0].AffectedEntities), findings[0].Count)
	}
}
