package organization

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestWrongOuOnDisabledAccount_DisabledComputerInDefaultContainerFires
// covers the nominal case: a disabled computer whose direct parent is the
// first-level CN=Computers container must be flagged here.
func TestWrongOuOnDisabledAccount_DisabledComputerInDefaultContainerFires(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:             "CN=PC01$,CN=Computers,DC=contoso,DC=com",
				SAMAccountName: "PC01$",
				Disabled:       true,
			},
		},
	}

	findings := NewWrongOuOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: a disabled computer directly in CN=Computers must fire", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityInfo {
		t.Errorf("severity = %q, want info", findings[0].Severity)
	}
}

// TestWrongOuOnDisabledAccount_DisabledComputerInOrganizationalUnitNotFlagged
// covers the negative case: a disabled computer organized into an OU must
// not fire.
func TestWrongOuOnDisabledAccount_DisabledComputerInOrganizationalUnitNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:             "CN=PC02$,OU=Workstations,DC=contoso,DC=com",
				SAMAccountName: "PC02$",
				Disabled:       true,
			},
		},
	}

	findings := NewWrongOuOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a disabled computer organized in an OU must not fire", findings[0].Count)
	}
}

// TestWrongOuOnDisabledAccount_ExcludesActiveComputers is the guard's
// mutation kill: an enabled computer carrying the exact same
// default-container DN a disabled true positive would must not fire here -
// it is reported instead, at Low, by WrongOuDetector.
func TestWrongOuOnDisabledAccount_ExcludesActiveComputers(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:             "CN=PC03$,CN=Computers,DC=contoso,DC=com",
				SAMAccountName: "PC03$",
			},
		},
	}

	findings := NewWrongOuOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: an enabled computer with the exact same default-container DN must not fire in the disabled-account detector", findings[0].Count)
	}
}

// TestWrongOuOnDisabledAccount_CaseInsensitiveMatch covers
// case-insensitivity: the detector lowercases the DN before matching, so a
// differently-cased DN must still fire when the account is disabled.
func TestWrongOuOnDisabledAccount_CaseInsensitiveMatch(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:             "cn=PC04$,CN=COMPUTERS,dc=CONTOSO,dc=COM",
				SAMAccountName: "PC04$",
				Disabled:       true,
			},
		},
	}

	findings := NewWrongOuOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: matching must be case-insensitive", findings[0].Count)
	}
}

// TestWrongOuOnDisabledAccount_CountMatchesAffectedEntitiesLength covers
// the count demanded by the ticket: with a mix of matching, non-matching
// and enabled computers, Count and len(AffectedEntities) must both equal
// the number of matching DISABLED entities, no more and no less.
func TestWrongOuOnDisabledAccount_CountMatchesAffectedEntitiesLength(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=PC05$,CN=Computers,DC=contoso,DC=com", SAMAccountName: "PC05$", Disabled: true},
			{DN: "CN=PC06$,CN=Computers,DC=contoso,DC=com", SAMAccountName: "PC06$", Disabled: true},
			{DN: "CN=PC07$,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "PC07$", Disabled: true},
			{DN: "CN=PC09$,CN=Computers,DC=contoso,DC=com", SAMAccountName: "PC09$"},
		},
	}

	findings := NewWrongOuOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 2 {
		t.Fatalf("Count = %d, want 2", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != findings[0].Count {
		t.Fatalf("len(AffectedEntities) = %d, want %d (equal to Count)", len(findings[0].AffectedEntities), findings[0].Count)
	}
}

// TestWrongOu_PartitionIsExhaustive covers both detectors together: a
// computer directly in the default Computers container is counted by
// exactly one of the two - active or disabled - never both, never
// neither.
func TestWrongOu_PartitionIsExhaustive(t *testing.T) {
	computers := []types.Computer{
		{DN: "CN=active-match$,CN=Computers,DC=contoso,DC=com"},
		{DN: "CN=disabled-match$,CN=Computers,DC=contoso,DC=com", Disabled: true},
		{DN: "CN=active-clean$,OU=Workstations,DC=contoso,DC=com"},
		{DN: "CN=disabled-clean$,OU=Workstations,DC=contoso,DC=com", Disabled: true},
	}
	data := &audit.DetectorData{Computers: computers, IncludeDetails: true}

	active := NewWrongOuDetector().Detect(context.Background(), data)
	disabled := NewWrongOuOnDisabledAccountDetector().Detect(context.Background(), data)

	if active[0].Count != 1 {
		t.Fatalf("active half: want 1 (active-match), got %d", active[0].Count)
	}
	if disabled[0].Count != 1 {
		t.Fatalf("disabled half: want 1 (disabled-match), got %d", disabled[0].Count)
	}
}
