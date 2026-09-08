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
		Computers: []types.Computer{
			{DN: lapsComputerDN, SAMAccountName: "WKS04$", ObjectSID: computerSID},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: lapsComputerDN, Trustee: reader1, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDLAPSPassword},
			{ObjectDN: lapsComputerDN, Trustee: reader2, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDLAPSPassword},
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
		Computers: []types.Computer{
			{DN: lapsComputerDN, SAMAccountName: "WKS05$", ObjectSID: computerSID},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: lapsComputerDN, Trustee: "S-1-5-18", AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDLAPSPassword},
			{ObjectDN: lapsComputerDN, Trustee: domainAdminsSID, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDLAPSPassword},
			{ObjectDN: lapsComputerDN, Trustee: nonAdminSID, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDLAPSPassword},
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
		Computers: []types.Computer{
			{DN: lapsComputerDN, SAMAccountName: "WKS06$", ObjectSID: computerSID},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: lapsComputerDN, Trustee: reader1, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDLAPSPassword},
			{ObjectDN: lapsComputerDN, Trustee: reader2, AccessMask: types.MaskControlAccess, AceType: "ACCESS_DENIED", ObjectType: types.GUIDLAPSPassword},
		},
	}

	findings := NewLapsPasswordLeakedDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("a DENY ace must not count as a reader, got count=%d", findings[0].Count)
	}
}
