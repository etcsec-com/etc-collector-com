package status

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestAdminCountOnDisabledAccount_DisabledComputerWithAdminCountTrueFires(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WS-30,OU=Workstations,DC=contoso,DC=com", Disabled: true, AdminCount: true},
		},
	}
	findings := NewAdminCountOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("a disabled computer with AdminCount=true must fire, got count=%d", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityInfo {
		t.Errorf("severity = %q, want info", findings[0].Severity)
	}
}

func TestAdminCountOnDisabledAccount_DisabledComputerWithAdminCountFalseDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WS-31,OU=Workstations,DC=contoso,DC=com", Disabled: true, AdminCount: false},
		},
	}
	findings := NewAdminCountOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("a disabled computer with AdminCount=false must not fire, got count=%d", findings[0].Count)
	}
}

// TestAdminCountOnDisabledAccount_ExcludesActiveComputers is the guard's
// mutation kill: an enabled computer carrying the exact same AdminCount=true
// must not fire here - it is reported instead, at Info, by
// AdminCountDetector.
func TestAdminCountOnDisabledAccount_ExcludesActiveComputers(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WS-32,OU=Workstations,DC=contoso,DC=com", AdminCount: true},
		},
	}
	findings := NewAdminCountOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("an enabled computer with AdminCount=true must not fire in the disabled-account detector, got count=%d", findings[0].Count)
	}
}

func TestAdminCountOnDisabledAccount_CountMatchesAffectedEntitiesLength(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=WS-33,OU=Workstations,DC=contoso,DC=com", Disabled: true, AdminCount: true},
			{DN: "CN=WS-34,OU=Workstations,DC=contoso,DC=com", Disabled: true, AdminCount: false},
			{DN: "CN=WS-35,OU=Workstations,DC=contoso,DC=com", Disabled: true, AdminCount: true},
			{DN: "CN=WS-36,OU=Workstations,DC=contoso,DC=com", AdminCount: true},
		},
	}
	findings := NewAdminCountOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 2 {
		t.Fatalf("expected count=2 for a mixed list (enabled entry excluded), got %d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != findings[0].Count {
		t.Fatalf("AffectedEntities length %d must match Count %d", len(findings[0].AffectedEntities), findings[0].Count)
	}
}

// TestAdminCount_PartitionIsExhaustive covers both detectors together: a
// computer with AdminCount=true is counted by exactly one of the two -
// active or disabled - never both, never neither.
func TestAdminCount_PartitionIsExhaustive(t *testing.T) {
	computers := []types.Computer{
		{DN: "CN=active-match", AdminCount: true},
		{DN: "CN=disabled-match", AdminCount: true, Disabled: true},
		{DN: "CN=active-clean", AdminCount: false},
		{DN: "CN=disabled-clean", AdminCount: false, Disabled: true},
	}
	data := &audit.DetectorData{Computers: computers, IncludeDetails: true}

	active := NewAdminCountDetector().Detect(context.Background(), data)
	disabled := NewAdminCountOnDisabledAccountDetector().Detect(context.Background(), data)

	if active[0].Count != 1 {
		t.Fatalf("active half: want 1 (active-match), got %d", active[0].Count)
	}
	if disabled[0].Count != 1 {
		t.Fatalf("disabled half: want 1 (disabled-match), got %d", disabled[0].Count)
	}
}
