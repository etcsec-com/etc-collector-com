package organization

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestWrongOu_DirectlyInDefaultContainerFires covers the nominal case: a
// computer whose direct parent is the first-level CN=Computers container
// must be flagged.
func TestWrongOu_DirectlyInDefaultContainerFires(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:             "CN=PC01$,CN=Computers,DC=contoso,DC=com",
				SAMAccountName: "PC01$",
			},
		},
	}

	findings := NewWrongOuDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: a computer directly in CN=Computers must fire", findings[0].Count)
	}
}

// TestWrongOu_ComputerInOrganizationalUnitNotFlagged covers the negative
// case: a computer organized into an OU must not fire.
func TestWrongOu_ComputerInOrganizationalUnitNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:             "CN=PC02$,OU=Workstations,DC=contoso,DC=com",
				SAMAccountName: "PC02$",
			},
		},
	}

	findings := NewWrongOuDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a computer organized in an OU must not fire", findings[0].Count)
	}
}

// TestWrongOu_NestedComputersContainerUnderOUNotFlagged pins a structural
// limitation of the detector rather than fixing it (wrong-ou.go is out of
// scope for this ticket): the substring check `,cn=computers,dc=` only
// matches when CN=Computers is the DIRECT child of the domain head. A
// container object also literally named "Computers" but nested one level
// deeper (here under an OU) never produces that substring - what follows
// "cn=computers" is ",ou=legacy" rather than ",dc=". A computer placed
// there is silently never flagged by this detector, whatever its real
// organizational status.
func TestWrongOu_NestedComputersContainerUnderOUNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:             "CN=PC03$,CN=Computers,OU=Legacy,DC=contoso,DC=com",
				SAMAccountName: "PC03$",
			},
		},
	}

	findings := NewWrongOuDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a CN=Computers container nested under an OU is not the first-level default container this substring check targets", findings[0].Count)
	}
}

// TestWrongOu_CaseInsensitiveMatch covers case-insensitivity: the detector
// lowercases the DN before matching, so a differently-cased DN must still
// fire.
func TestWrongOu_CaseInsensitiveMatch(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:             "cn=PC04$,CN=COMPUTERS,dc=CONTOSO,dc=COM",
				SAMAccountName: "PC04$",
			},
		},
	}

	findings := NewWrongOuDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: matching must be case-insensitive", findings[0].Count)
	}
}

// TestWrongOu_ExcludesDisabledComputers is the guard's mutation kill: a
// disabled computer directly in CN=Computers, carrying the exact same
// default-container DN a live true positive would, must not fire here
// anymore - it is reported instead, at Info, by
// WrongOuOnDisabledAccountDetector.
func TestWrongOu_ExcludesDisabledComputers(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:             "CN=PC08$,CN=Computers,DC=contoso,DC=com",
				SAMAccountName: "PC08$",
				Disabled:       true,
			},
		},
	}

	findings := NewWrongOuDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a disabled computer with the exact same default-container DN must not fire in the active detector", findings[0].Count)
	}
}

// TestWrongOu_CountMatchesAffectedEntitiesLength covers the count demanded
// by the ticket: with a mix of matching, non-matching and disabled
// computers, Count and len(AffectedEntities) must both equal the number of
// matching ENABLED entities, no more and no less - the disabled entry is
// excluded by the guard, not just by DN.
func TestWrongOu_CountMatchesAffectedEntitiesLength(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=PC05$,CN=Computers,DC=contoso,DC=com", SAMAccountName: "PC05$"},
			{DN: "CN=PC06$,CN=Computers,DC=contoso,DC=com", SAMAccountName: "PC06$"},
			{DN: "CN=PC07$,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "PC07$"},
			{DN: "CN=PC09$,CN=Computers,DC=contoso,DC=com", SAMAccountName: "PC09$", Disabled: true},
		},
	}

	findings := NewWrongOuDetector().Detect(context.Background(), data)
	if findings[0].Count != 2 {
		t.Fatalf("Count = %d, want 2", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != findings[0].Count {
		t.Fatalf("len(AffectedEntities) = %d, want %d (equal to Count)", len(findings[0].AffectedEntities), findings[0].Count)
	}
}
