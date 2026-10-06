package laps

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const lapsComputerDN = "CN=WKS01,OU=Workstations,DC=contoso,DC=com"

// realLAPSGUID stands in for a schemaIDGUID read live from a forest's
// schema. It is deliberately NOT types.GUIDLAPSPassword: ms-Mcs-AdmPwd is a
// third-party schema extension, so its schemaIDGUID is generated per forest
// at schema-extension time, not fixed like a native AD extended right.
// Using a distinct fixture value here proves the detector matches against
// the resolved DomainInfo field, not the stale constant - the previous
// version of these tests built the ACE's ObjectType from
// types.GUIDLAPSPassword and compared it to the same constant, so they
// would have passed unchanged no matter what value that constant held.
const realLAPSGUID = "15d8deef-e038-4cd9-97d8-bca99d8b5156"

// TestLapsPasswordReadable_FiresOnNonAdminReadACE:
// Computer.LAPSPasswordReadableByNonAdmins is declared but never assigned
// anywhere in the collectors, so the detector always read a
// permanently-false field. The signal is already collected: the LDAP
// provider pulls each computer's nTSecurityDescriptor into data.ACLEntries,
// and CONTROL_ACCESS + the resolved ms-Mcs-AdmPwd schemaIDGUID on an ACE is
// the exact extended right that grants LAPS password read access.
func TestLapsPasswordReadable_FiresOnNonAdminReadACE(t *testing.T) {
	domainSID := "S-1-5-21-1-2-3"
	computerSID := domainSID + "-2001"
	nonAdminSID := domainSID + "-9001"

	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{LAPSPasswordSchemaGUID: realLAPSGUID},
		Computers: []types.Computer{
			{DN: lapsComputerDN, SAMAccountName: "WKS01$", ObjectSID: computerSID},
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

	findings := NewLapsPasswordReadableDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 for a non-admin holding CONTROL_ACCESS on the resolved LAPS password GUID, got %d", findings[0].Count)
	}
}

// TestLapsPasswordReadable_AdminOnlyDoesNotFire guards against
// over-filtering: only Domain Admins/BUILTIN\Administrators/SYSTEM holding
// the right is the expected baseline and must not fire.
func TestLapsPasswordReadable_AdminOnlyDoesNotFire(t *testing.T) {
	domainSID := "S-1-5-21-1-2-3"
	computerSID := domainSID + "-2002"
	domainAdminsSID := domainSID + "-512"

	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{LAPSPasswordSchemaGUID: realLAPSGUID},
		Computers: []types.Computer{
			{DN: lapsComputerDN, SAMAccountName: "WKS02$", ObjectSID: computerSID},
		},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   lapsComputerDN,
				Trustee:    domainAdminsSID,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
				ObjectType: realLAPSGUID,
			},
		},
	}

	findings := NewLapsPasswordReadableDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (Domain Admins is expected baseline), got %d", findings[0].Count)
	}
}

// TestLapsPasswordReadable_StaleConstantDoesNotFire: an ACE built with the
// known-wrong types.GUIDLAPSPassword constant (measured as
// e91556f8-b3c8-4b66-b3c8-4b0c8ac2c45b in code against a real per-forest
// schemaIDGUID of 15d8deef-e038-4cd9-97d8-bca99d8b5156 on a lab forest) must
// NOT match once DomainInfo carries the correctly resolved value.
func TestLapsPasswordReadable_StaleConstantDoesNotFire(t *testing.T) {
	domainSID := "S-1-5-21-1-2-3"
	computerSID := domainSID + "-2003"
	nonAdminSID := domainSID + "-9001"

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
				ObjectType: types.GUIDLAPSPassword,
			},
		},
	}

	findings := NewLapsPasswordReadableDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0: ACE carries the stale constant, not the resolved schema GUID, got %d", findings[0].Count)
	}
}

// TestLapsPasswordReadable_UnresolvedSchemaGUIDDoesNotFire: if the collector
// never resolved LAPSPasswordSchemaGUID (DomainInfo nil, or the LAPS schema
// query found nothing), the detector must not match anything rather than
// falling back to a guessed value.
func TestLapsPasswordReadable_UnresolvedSchemaGUIDDoesNotFire(t *testing.T) {
	domainSID := "S-1-5-21-1-2-3"
	computerSID := domainSID + "-2004"
	nonAdminSID := domainSID + "-9001"

	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: lapsComputerDN, SAMAccountName: "WKS04$", ObjectSID: computerSID},
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

	findings := NewLapsPasswordReadableDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0: DomainInfo is nil, no schema GUID was resolved, got %d", findings[0].Count)
	}
}

// TestLapsPasswordReadable_EmptyObjectTypeWithUnresolvedGUIDDoesNotFireAcrossFleet
// covers the one entry shape none of the tests above build: an ACE whose
// ObjectType is "" (the real shape of a GPO ACL ACE, which has no object
// type to offer) evaluated against a DomainInfo that IS present but whose
// LAPSPasswordSchemaGUID resolved to "" - a forest where the schema lookup
// ran but found nothing (no LAPS installed), unlike
// UnresolvedSchemaGUIDDoesNotFire above which leaves DomainInfo nil
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
// misconfiguration - would be counted as a LAPS reader on every affected
// computer, not just one. Two computers are used here (not one) so that
// removing the guard pair visibly floods the whole fleet rather than
// reading as a single edge case.
func TestLapsPasswordReadable_EmptyObjectTypeWithUnresolvedGUIDDoesNotFireAcrossFleet(t *testing.T) {
	domainSID := "S-1-5-21-1-2-3"
	computerDN1 := "CN=WKS10,OU=Workstations,DC=contoso,DC=com"
	computerDN2 := "CN=WKS11,OU=Workstations,DC=contoso,DC=com"
	computerSID1 := domainSID + "-2010"
	computerSID2 := domainSID + "-2011"
	nonAdminSID := domainSID + "-9020"

	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{LAPSPasswordSchemaGUID: ""},
		Computers: []types.Computer{
			{DN: computerDN1, SAMAccountName: "WKS10$", ObjectSID: computerSID1},
			{DN: computerDN2, SAMAccountName: "WKS11$", ObjectSID: computerSID2},
		},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   computerDN1,
				Trustee:    nonAdminSID,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
				ObjectType: "", // unresolved objectType, same shape as the GPO ACL call site
			},
			{
				ObjectDN:   computerDN2,
				Trustee:    nonAdminSID,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
				ObjectType: "",
			},
		},
	}

	findings := NewLapsPasswordReadableDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0: an empty ObjectType must not match an unresolved LAPS schema GUID, got %d (would mean the whole fleet misfired)", findings[0].Count)
	}
}
