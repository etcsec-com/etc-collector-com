package laps

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const lapsComputerDN = "CN=WKS01,OU=Workstations,DC=contoso,DC=com"

// TestLapsPasswordReadable_FiresOnNonAdminReadACE:
// Computer.LAPSPasswordReadableByNonAdmins is declared but never assigned
// anywhere in the collectors, so the detector always read a
// permanently-false field. The signal is already collected: the LDAP
// provider pulls each computer's nTSecurityDescriptor into data.ACLEntries,
// and CONTROL_ACCESS + types.GUIDLAPSPassword on an ACE is the exact
// extended right the attack-graph BFS already classifies as
// RelReadLAPSPassword.
func TestLapsPasswordReadable_FiresOnNonAdminReadACE(t *testing.T) {
	domainSID := "S-1-5-21-1-2-3"
	computerSID := domainSID + "-2001"
	nonAdminSID := domainSID + "-9001"

	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: lapsComputerDN, SAMAccountName: "WKS01$", ObjectSID: computerSID},
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
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 for a non-admin holding CONTROL_ACCESS on the LAPS password ACE, got %d", findings[0].Count)
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
		Computers: []types.Computer{
			{DN: lapsComputerDN, SAMAccountName: "WKS02$", ObjectSID: computerSID},
		},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   lapsComputerDN,
				Trustee:    domainAdminsSID,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
				ObjectType: types.GUIDLAPSPassword,
			},
		},
	}

	findings := NewLapsPasswordReadableDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (Domain Admins is expected baseline), got %d", findings[0].Count)
	}
}
