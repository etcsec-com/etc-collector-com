package dangerous

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Fixture values are literals, never the detector's own unexported
// constants: a drift in the detector's GUID/mask would otherwise be
// invisible to these tests (the LAPS GUID lesson).
const (
	reanimateFixtureDomainSID = "S-1-5-21-1111111111-2222222222-3333333333"
	reanimateFixtureGUID      = "45ec5156-db7e-47bb-b53f-dbeb2d03c40f" // Reanimate-Tombstones, forest-fixed extended right
	reanimateOtherGUID        = "00299570-246d-11d0-a768-00aa006e0529" // User-Force-Change-Password, a different forest-fixed extended right
	reanimateControlAccess    = 0x00000100
	reanimateWriteProperty    = 0x00000020

	reanimateFixtureDN      = "OU=FixtureA,DC=example,DC=com"
	reanimateSystemACEDN    = "OU=FixtureB,DC=example,DC=com"
	reanimateWrongGUIDACEDN = "OU=FixtureC,DC=example,DC=com"
	reanimateWrongMaskACEDN = "OU=FixtureD,DC=example,DC=com"

	reanimateOrdinaryTrustee = reanimateFixtureDomainSID + "-1105"
)

func reanimateData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		DomainInfo: &types.DomainInfo{
			DomainDN:  "DC=example,DC=com",
			DomainSID: reanimateFixtureDomainSID,
		},
	}
}

// TestReanimateTombstones_LabPlantWitnesses mirrors a live lab plant of 3
// ACEs sharing one DACL: a matching ACE on its own object fires alone, a
// SYSTEM trustee on the same GUID does not (privileged filter), and the same
// mask/trustee on a different extended right does not (GUID filter).
func TestReanimateTombstones_LabPlantWitnesses(t *testing.T) {
	matching := types.ACLEntry{
		ObjectDN:   reanimateFixtureDN,
		Trustee:    reanimateOrdinaryTrustee,
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: reanimateControlAccess,
		ObjectType: reanimateFixtureGUID,
	}
	systemTrustee := types.ACLEntry{
		ObjectDN:   reanimateSystemACEDN,
		Trustee:    "S-1-5-18",
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: reanimateControlAccess,
		ObjectType: reanimateFixtureGUID,
	}
	wrongGUID := types.ACLEntry{
		ObjectDN:   reanimateWrongGUIDACEDN,
		Trustee:    reanimateOrdinaryTrustee,
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: reanimateControlAccess,
		ObjectType: reanimateOtherGUID,
	}

	data := reanimateData(matching, systemTrustee, wrongGUID)
	d := NewReanimateTombstonesDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (only the matching ACE on %s - SYSTEM trustee and wrong GUID must not fire)", findings[0].Count, reanimateFixtureDN)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].DN != reanimateFixtureDN {
		t.Fatalf("AffectedEntities = %+v, want exactly [%s]", findings[0].AffectedEntities, reanimateFixtureDN)
	}
}

// TestReanimateTombstones_DomainSuffixPrivilegedTrustee covers the dynamic
// half of privilegedSIDs (DomainSID+suffix from types.PrivilegedSIDSuffixes),
// not just the 3 hardcoded well-known SIDs exercised above.
func TestReanimateTombstones_DomainSuffixPrivilegedTrustee(t *testing.T) {
	domainAdmins := types.ACLEntry{
		ObjectDN:   reanimateFixtureDN,
		Trustee:    reanimateFixtureDomainSID + "-512", // Domain Admins
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: reanimateControlAccess,
		ObjectType: reanimateFixtureGUID,
	}
	data := reanimateData(domainAdmins)
	d := NewReanimateTombstonesDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (Domain Admins is a domainSID-suffix privileged trustee)", findings[0].Count)
	}
}

// TestReanimateTombstones_AceTypeMustContainAllowed covers the first filter:
// a Contains match on "ALLOWED", not an equality - a DENY-typed ACE must not
// fire even with the matching mask/GUID/trustee, while the non-object
// ACCESS_ALLOWED string (not just ACCESS_ALLOWED_OBJECT) must still pass it.
func TestReanimateTombstones_AceTypeMustContainAllowed(t *testing.T) {
	denyType := types.ACLEntry{
		ObjectDN:   reanimateFixtureDN,
		Trustee:    reanimateOrdinaryTrustee,
		AceType:    "ACCESS_DENIED_OBJECT",
		AccessMask: reanimateControlAccess,
		ObjectType: reanimateFixtureGUID,
	}
	data := reanimateData(denyType)
	d := NewReanimateTombstonesDetector()
	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (ACCESS_DENIED_OBJECT does not contain ALLOWED)", findings[0].Count)
	}

	nonObjectAllowed := types.ACLEntry{
		ObjectDN:   reanimateFixtureDN,
		Trustee:    reanimateOrdinaryTrustee,
		AceType:    "ACCESS_ALLOWED",
		AccessMask: reanimateControlAccess,
		ObjectType: reanimateFixtureGUID,
	}
	data2 := reanimateData(nonObjectAllowed)
	findings2 := d.Detect(context.Background(), data2)
	if findings2[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (plain ACCESS_ALLOWED contains ALLOWED too)", findings2[0].Count)
	}
}

// TestReanimateTombstones_MutationCoverage is the fixture eprouvee par
// cassure for M1 (GUID constant swapped), M2 (privileged-skip removed) and
// M3 (ControlAccess mask check removed). Each ACE lives on its own DN so
// GetUniqueObjects' DN-level dedup cannot mask a mutation that makes a
// witness fire in addition to the baseline one.
func TestReanimateTombstones_MutationCoverage(t *testing.T) {
	matching := types.ACLEntry{
		ObjectDN:   reanimateFixtureDN,
		Trustee:    reanimateOrdinaryTrustee,
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: reanimateControlAccess,
		ObjectType: reanimateFixtureGUID,
	}
	systemTrustee := types.ACLEntry{
		ObjectDN:   reanimateSystemACEDN,
		Trustee:    "S-1-5-18",
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: reanimateControlAccess,
		ObjectType: reanimateFixtureGUID,
	}
	wrongGUID := types.ACLEntry{
		ObjectDN:   reanimateWrongGUIDACEDN,
		Trustee:    reanimateOrdinaryTrustee,
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: reanimateControlAccess,
		ObjectType: reanimateOtherGUID,
	}
	wrongMask := types.ACLEntry{
		ObjectDN:   reanimateWrongMaskACEDN,
		Trustee:    reanimateOrdinaryTrustee,
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: reanimateWriteProperty, // no ControlAccess bit
		ObjectType: reanimateFixtureGUID,
	}

	data := reanimateData(matching, systemTrustee, wrongGUID, wrongMask)
	d := NewReanimateTombstonesDetector()
	findings := d.Detect(context.Background(), data)

	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want exactly 1 (kills M1: GUID swap would drop the matching ACE to 0; "+
			"kills M2: privileged-skip removal would add %s; kills M3: ControlAccess-check removal would add %s)",
			findings[0].Count, reanimateSystemACEDN, reanimateWrongMaskACEDN)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].DN != reanimateFixtureDN {
		t.Fatalf("AffectedEntities = %+v, want exactly [%s]", findings[0].AffectedEntities, reanimateFixtureDN)
	}
}
