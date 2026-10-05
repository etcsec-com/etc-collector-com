package laps

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestLapsPasswordLeaked_SingleNonAdminReaderDoesNotFire is the RED->GREEN
// case for a regression and the boundary that distinguishes LEAKED from READABLE: a
// single dedicated LAPS-read group is the expected deployment shape, not an
// "excessive readers" finding. Before the fix this always read the
// permanently-false Computer.LAPSPasswordExcessiveReaders field, so it never
// fired regardless of input - this test alone would have passed against the
// old code by coincidence (both want Count=0), which is why the next test is
// the one that actually proves the fix red on old code.
func TestLapsPasswordLeaked_SingleNonAdminReaderDoesNotFire(t *testing.T) {
	domainSID := "S-1-5-21-1-2-3"
	computerSID := domainSID + "-2003"
	nonAdminSID := domainSID + "-9002"

	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{LAPSPasswordSchemaGUID: realLAPSGUID},
		Computers: []types.Computer{
			{DN: lapsComputerDN, SAMAccountName: "WKS03$", ObjectSID: computerSID},
		},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   lapsComputerDN,
				Trustee:    nonAdminSID,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
				ObjectType: realLAPSGUID,
			},
		},
	}

	findings := NewLapsPasswordLeakedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("a single non-admin reader is the expected LAPS deployment shape, got count=%d", findings[0].Count)
	}
}

// TestLapsPasswordLeaked_MultipleNonAdminReadersFires is the RED->GREEN case:
// before the fix the detector always read the permanently-false
// Computer.LAPSPasswordExcessiveReaders field and could never fire, even with
// two distinct non-admin trustees both holding CONTROL_ACCESS on the LAPS
// password attribute of the same computer.
func TestLapsPasswordLeaked_MultipleNonAdminReadersFires(t *testing.T) {
	domainSID := "S-1-5-21-1-2-3"
	computerSID := domainSID + "-2004"
	reader1 := domainSID + "-9003"
	reader2 := domainSID + "-9004"

	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{LAPSPasswordSchemaGUID: realLAPSGUID},
		Computers: []types.Computer{
			{DN: lapsComputerDN, SAMAccountName: "WKS04$", ObjectSID: computerSID},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: lapsComputerDN, Trustee: reader1, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: realLAPSGUID},
			{ObjectDN: lapsComputerDN, Trustee: reader2, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: realLAPSGUID},
		},
	}

	findings := NewLapsPasswordLeakedDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("two distinct non-admin readers on the same computer must fire, got count=%d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("finding must be actionable, got %d entities", len(findings[0].AffectedEntities))
	}
}

// TestLapsPasswordLeaked_AdminReadersDoNotCount guards against
// over-filtering: SYSTEM/Domain Admins/BUILTIN\Administrators plus a single
// real non-admin reader is still the expected baseline (only 1 non-admin
// reader), not "excessive".
func TestLapsPasswordLeaked_AdminReadersDoNotCount(t *testing.T) {
	domainSID := "S-1-5-21-1-2-3"
	computerSID := domainSID + "-2005"
	domainAdminsSID := domainSID + "-512"
	nonAdminSID := domainSID + "-9005"

	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{LAPSPasswordSchemaGUID: realLAPSGUID},
		Computers: []types.Computer{
			{DN: lapsComputerDN, SAMAccountName: "WKS05$", ObjectSID: computerSID},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: lapsComputerDN, Trustee: "S-1-5-18", AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: realLAPSGUID},
			{ObjectDN: lapsComputerDN, Trustee: domainAdminsSID, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: realLAPSGUID},
			{ObjectDN: lapsComputerDN, Trustee: nonAdminSID, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: realLAPSGUID},
		},
	}

	findings := NewLapsPasswordLeakedDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("builtin-admin trustees must not count toward excessive readers, got count=%d", findings[0].Count)
	}
}

// TestLapsPasswordLeaked_DenyAceDoesNotCount covers DET_10.
func TestLapsPasswordLeaked_DenyAceDoesNotCount(t *testing.T) {
	domainSID := "S-1-5-21-1-2-3"
	computerSID := domainSID + "-2006"
	reader1 := domainSID + "-9006"
	reader2 := domainSID + "-9007"

	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{LAPSPasswordSchemaGUID: realLAPSGUID},
		Computers: []types.Computer{
			{DN: lapsComputerDN, SAMAccountName: "WKS06$", ObjectSID: computerSID},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: lapsComputerDN, Trustee: reader1, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: realLAPSGUID},
			{ObjectDN: lapsComputerDN, Trustee: reader2, AccessMask: types.MaskControlAccess, AceType: "ACCESS_DENIED", ObjectType: realLAPSGUID},
		},
	}

	findings := NewLapsPasswordLeakedDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("a DENY ace must not count as a reader, got count=%d", findings[0].Count)
	}
}

// TestLapsPasswordLeaked_StaleConstantDoesNotCount: two ACEs built with the
// known-wrong types.GUIDLAPSPassword constant must not be counted as readers
// once DomainInfo carries the correctly resolved, distinct schema GUID.
func TestLapsPasswordLeaked_StaleConstantDoesNotCount(t *testing.T) {
	domainSID := "S-1-5-21-1-2-3"
	computerSID := domainSID + "-2007"
	reader1 := domainSID + "-9008"
	reader2 := domainSID + "-9009"

	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{LAPSPasswordSchemaGUID: realLAPSGUID},
		Computers: []types.Computer{
			{DN: lapsComputerDN, SAMAccountName: "WKS07$", ObjectSID: computerSID},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: lapsComputerDN, Trustee: reader1, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDLAPSPassword},
			{ObjectDN: lapsComputerDN, Trustee: reader2, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDLAPSPassword},
		},
	}

	findings := NewLapsPasswordLeakedDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0: ACEs carry the stale constant, not the resolved schema GUID, got %d", findings[0].Count)
	}
}

// TestLapsPasswordLeaked_UnresolvedSchemaGUIDDoesNotCount: if the collector
// never resolved LAPSPasswordSchemaGUID (DomainInfo nil), the detector must
// not match anything rather than falling back to a guessed value.
func TestLapsPasswordLeaked_UnresolvedSchemaGUIDDoesNotCount(t *testing.T) {
	domainSID := "S-1-5-21-1-2-3"
	computerSID := domainSID + "-2008"
	reader1 := domainSID + "-9010"
	reader2 := domainSID + "-9011"

	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: lapsComputerDN, SAMAccountName: "WKS08$", ObjectSID: computerSID},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: lapsComputerDN, Trustee: reader1, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: realLAPSGUID},
			{ObjectDN: lapsComputerDN, Trustee: reader2, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: realLAPSGUID},
		},
	}

	findings := NewLapsPasswordLeakedDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0: DomainInfo is nil, no schema GUID was resolved, got %d", findings[0].Count)
	}
}

// TestLapsPasswordLeaked_EmptyObjectTypeWithUnresolvedGUIDDoesNotCountAcrossFleet
// covers the one entry shape none of the tests above build: an ACE whose
// ObjectType is "" (the real shape of a GPO ACL ACE, which has no object
// type to offer) evaluated against a DomainInfo that IS present but whose
// LAPSPasswordSchemaGUID resolved to "" - a forest where the schema lookup
// ran but found nothing (no LAPS installed), unlike
// UnresolvedSchemaGUIDDoesNotCount above which leaves DomainInfo nil
// entirely (schema lookup never ran at all). Both leave lapsGUID == "" in
// the detector, but only this shape can make ObjectType == "" collide with
// it under EqualFold("", "") == true.
//
// The detector guards this with two clauses:
//
//	if ace.ObjectType == "" || lapsGUID == "" || !strings.EqualFold(ace.ObjectType, lapsGUID) { continue }
//
// On THIS input the two leading clauses are redundant with each other -
// either one alone already discards the ACE, so no single-clause mutation
// can turn this test red (proven in the VERDICT by breaking each clause in
// isolation, then both at once). They still matter together: drop BOTH and
// EqualFold("", "") matches, so every ControlAccess ACE without an object
// type - which includes ordinary GPO ACEs, not just a hypothetical
// misconfiguration - would be counted as a LAPS reader. Two distinct
// trustees per computer are used here (unlike the sibling READABLE test,
// which only needs one) because LEAKED only fires past a single reader;
// without a second distinct trustee on the same computer, removing the
// guard pair would silently stay green here even though the ACE matched.
// Two computers are used so the failure reads as flooding the fleet, not a
// single edge case.
func TestLapsPasswordLeaked_EmptyObjectTypeWithUnresolvedGUIDDoesNotCountAcrossFleet(t *testing.T) {
	domainSID := "S-1-5-21-1-2-3"
	computerDN1 := "CN=WKS20,OU=Workstations,DC=contoso,DC=com"
	computerDN2 := "CN=WKS21,OU=Workstations,DC=contoso,DC=com"
	computerSID1 := domainSID + "-2020"
	computerSID2 := domainSID + "-2021"
	reader1 := domainSID + "-9030"
	reader2 := domainSID + "-9031"
	reader3 := domainSID + "-9032"
	reader4 := domainSID + "-9033"

	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{LAPSPasswordSchemaGUID: ""},
		Computers: []types.Computer{
			{DN: computerDN1, SAMAccountName: "WKS20$", ObjectSID: computerSID1},
			{DN: computerDN2, SAMAccountName: "WKS21$", ObjectSID: computerSID2},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: computerDN1, Trustee: reader1, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: ""}, // unresolved objectType, same shape as the GPO ACL call site
			{ObjectDN: computerDN1, Trustee: reader2, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: ""},
			{ObjectDN: computerDN2, Trustee: reader3, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: ""},
			{ObjectDN: computerDN2, Trustee: reader4, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: ""},
		},
	}

	findings := NewLapsPasswordLeakedDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0: an empty ObjectType must not match an unresolved LAPS schema GUID, got %d (would mean the whole fleet misfired)", findings[0].Count)
	}
}
