package other

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// BADSUCCESSOR_DMSA_ESCALATION reported 288 criticals on DC01, every
// one of them a user account nested under an OU (qa verdict §2). These tests
// pin both directions: the false positive must die, the true positive must
// survive.

const (
	bsDomainDN = "DC=example,DC=com"
	bsOUDN     = "OU=IT,OU=Tokyo," + bsDomainDN
	bsUserDN   = "CN=Akira Jackson," + bsOUDN // the exact FP shape from DC01
	bsHelpdesk = "S-1-5-21-1234567890-1111111111-2222222222-1337"
	bsFullCtrl = 0x000F01FF // full control - carries CreateChild (0x1)
)

// bsWS2025DC is a Windows Server 2025 domain controller - the precondition
// Akamai's BadSuccessor research requires for the dMSA feature to exist at
// all. Included by default in bsData so every existing test in this file
// keeps exercising the ACE/container logic (this file's actual subject)
// rather than accidentally tripping the "no WS2025 DC" severity
// downgrade; that downgrade gets its own dedicated test.
var bsWS2025DC = types.Computer{
	DN:                 "CN=DC01," + bsDomainDN,
	SAMAccountName:     "DC01$",
	OperatingSystem:    "Windows Server 2025 Standard",
	UserAccountControl: 0x2000, // SERVER_TRUST_ACCOUNT
}

// bsData wires ACEs plus the DN-indexed cache the detector reads object
// classes from (the engine builds it in collectData).
func bsData(aces []types.ACLEntry, byDN map[string]*audit.ObjectMeta) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		ObjectByDN:     byDN,
		Computers:      []types.Computer{bsWS2025DC},
	}
}

func bsIndex() map[string]*audit.ObjectMeta {
	return map[string]*audit.ObjectMeta{
		bsUserDN:   {DN: bsUserDN, Name: "Akira Jackson", EntityType: types.EntityTypeUser},
		bsOUDN:     {DN: bsOUDN, Name: "IT", EntityType: types.EntityTypeOU},
		bsDomainDN: {DN: bsDomainDN, Name: "example.com", EntityType: types.EntityTypeDomain},
	}
}

func bsDetect(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewBadSuccessorDMSADetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// TestBadSuccessorRequiresOUObjectClass covers acceptance §1: the detector must
// test the object CLASS, not a DN substring.
func TestBadSuccessorRequiresOUObjectClass(t *testing.T) {
	t.Run("user nested under an OU does NOT fire", func(t *testing.T) {
		// This is the DC01 false positive: full control on a USER whose DN
		// contains "OU=" because it lives under OU=IT,OU=Tokyo.
		f := bsDetect(t, bsData([]types.ACLEntry{{
			ObjectDN:   bsUserDN,
			Trustee:    bsHelpdesk,
			AccessMask: bsFullCtrl,
			AceType:    "ACCESS_ALLOWED",
		}}, bsIndex()))
		if f.Count != 0 {
			t.Fatalf("a user nested under an OU must not be reported as a dMSA container, got count=%d", f.Count)
		}
		if len(f.AffectedEntities) != 0 {
			t.Fatalf("count=0 must carry no entities, got %d", len(f.AffectedEntities))
		}
	})

	t.Run("real OU with CreateChild for a non-admin DOES fire", func(t *testing.T) {
		// The TRUE positive: a non-privileged principal can create arbitrary
		// child objects - including a dMSA - directly in an OU.
		f := bsDetect(t, bsData([]types.ACLEntry{{
			ObjectDN:   bsOUDN,
			Trustee:    bsHelpdesk,
			AccessMask: 0x1, // pure CreateChild, ObjectType empty = any class
			AceType:    "ACCESS_ALLOWED",
		}}, bsIndex()))
		if f.Count != 1 {
			t.Fatalf("CreateChild on a real OU must fire, got count=%d", f.Count)
		}
		if len(f.AffectedEntities) != 1 {
			t.Fatalf("a fired finding must be actionable, got %d entities", len(f.AffectedEntities))
		}
		if f.Severity != types.SeverityCritical {
			t.Errorf("severity = %q, want critical", f.Severity)
		}
	})

	t.Run("domain root counts as a container", func(t *testing.T) {
		f := bsDetect(t, bsData([]types.ACLEntry{{
			ObjectDN:   bsDomainDN,
			Trustee:    bsHelpdesk,
			AccessMask: bsFullCtrl,
			AceType:    "ACCESS_ALLOWED",
		}}, bsIndex()))
		if f.Count != 1 {
			t.Fatalf("CreateChild on the domain root must fire, got count=%d", f.Count)
		}
	})

	t.Run("unknown DN falls back to the leading RDN, not a substring", func(t *testing.T) {
		// Cache miss (LookupBatch failure). "OU=Orphan,…" IS an OU; the user
		// DN merely contains "OU=" and must still be rejected.
		orphanOU := "OU=Orphan," + bsDomainDN
		f := bsDetect(t, bsData([]types.ACLEntry{
			{ObjectDN: orphanOU, Trustee: bsHelpdesk, AccessMask: bsFullCtrl, AceType: "ACCESS_ALLOWED"},
			{ObjectDN: "CN=Nested," + orphanOU, Trustee: bsHelpdesk, AccessMask: bsFullCtrl, AceType: "ACCESS_ALLOWED"},
		}, nil))
		if f.Count != 1 {
			t.Fatalf("only the OU itself must fire on a cache miss, got count=%d", f.Count)
		}
	})
}

// TestBadSuccessorCountsUniqueObjects covers acceptance §1: count containers,
// not ACEs (286 unique objects were inflated to 288 findings on DC01).
func TestBadSuccessorCountsUniqueObjects(t *testing.T) {
	f := bsDetect(t, bsData([]types.ACLEntry{
		{ObjectDN: bsOUDN, Trustee: bsHelpdesk, AccessMask: bsFullCtrl, AceType: "ACCESS_ALLOWED"},
		{ObjectDN: bsOUDN, Trustee: "S-1-1-0", AccessMask: bsFullCtrl, AceType: "ACCESS_ALLOWED"}, // Everyone, same OU
	}, bsIndex()))
	if f.Count != 1 {
		t.Fatalf("two ACEs on the same OU = 1 exposed container, got count=%d", f.Count)
	}
	if len(f.AffectedEntities) != f.Count {
		t.Fatalf("count (%d) and entities (%d) must agree", f.Count, len(f.AffectedEntities))
	}
}

// TestBadSuccessorObjectTypeScope pins the remaining predicates: DENY ACEs,
// privileged trustees, and CreateChild scoped to a class that is not a dMSA.
func TestBadSuccessorObjectTypeScope(t *testing.T) {
	cases := []struct {
		name string
		ace  types.ACLEntry
		want int
	}{
		{
			name: "DENY ACE is not a grant",
			ace:  types.ACLEntry{ObjectDN: bsOUDN, Trustee: bsHelpdesk, AccessMask: bsFullCtrl, AceType: "ACCESS_DENIED"},
			want: 0,
		},
		{
			name: "privileged trustee is expected to hold it",
			ace:  types.ACLEntry{ObjectDN: bsOUDN, Trustee: "S-1-5-21-1234567890-1111111111-2222222222-512", AccessMask: bsFullCtrl, AceType: "ACCESS_ALLOWED"},
			want: 0,
		},
		{
			name: "CreateChild scoped to the computer class cannot create a dMSA",
			ace:  types.ACLEntry{ObjectDN: bsOUDN, Trustee: bsHelpdesk, AccessMask: 0x1, AceType: "ACCESS_ALLOWED", ObjectType: "bf967a86-0de6-11d0-a285-00aa003049e2"},
			want: 0,
		},
		{
			name: "CreateChild scoped to the dMSA class DOES fire",
			ace:  types.ACLEntry{ObjectDN: bsOUDN, Trustee: bsHelpdesk, AccessMask: 0x1, AceType: "ACCESS_ALLOWED", ObjectType: "0FEB936F-47B3-49F2-9386-1DEDC2C23765"},
			want: 1,
		},
		{
			name: "GenericAll subsumes CreateChild",
			ace:  types.ACLEntry{ObjectDN: bsOUDN, Trustee: bsHelpdesk, AccessMask: 0x10000000, AceType: "ACCESS_ALLOWED"},
			want: 1,
		},
		{
			name: "a mask without any create right does not fire",
			ace:  types.ACLEntry{ObjectDN: bsOUDN, Trustee: bsHelpdesk, AccessMask: 0x10, AceType: "ACCESS_ALLOWED"}, // READ_PROP
			want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := bsDetect(t, bsData([]types.ACLEntry{tc.ace}, bsIndex()))
			if f.Count != tc.want {
				t.Fatalf("count = %d, want %d", f.Count, tc.want)
			}
		})
	}
}

// TestBadSuccessorRequiresWindowsServer2025DC covers a real gap: Akamai's
// BadSuccessor research requires at least one Windows Server 2025 domain
// controller for the dMSA feature to exist. A prior version of this
// detector reported Critical regardless, even in a domain with no such DC
// - flagging an exposure that, today, is not actually exploitable.
func TestBadSuccessorRequiresWindowsServer2025DC(t *testing.T) {
	ace := []types.ACLEntry{{
		ObjectDN:   bsOUDN,
		Trustee:    bsHelpdesk,
		AccessMask: 0x1, // pure CreateChild, ObjectType empty = any class
		AceType:    "ACCESS_ALLOWED",
	}}

	t.Run("no Windows Server 2025 DC: still reported, but not Critical", func(t *testing.T) {
		data := &audit.DetectorData{
			IncludeDetails: true,
			ACLEntries:     ace,
			ObjectByDN:     bsIndex(),
			Computers: []types.Computer{{
				DN:                 "CN=DC01," + bsDomainDN,
				SAMAccountName:     "DC01$",
				OperatingSystem:    "Windows Server 2019 Standard",
				UserAccountControl: 0x2000,
			}},
		}
		f := bsDetect(t, data)
		if f.Count != 1 {
			t.Fatalf("the delegation itself is still a fact worth reporting, got count=%d", f.Count)
		}
		if f.Severity == types.SeverityCritical {
			t.Fatalf("severity = %q, want a downgrade from Critical: no WS2025 DC means the dMSA feature does not exist in this domain yet", f.Severity)
		}
		if f.Details["windowsServer2025DCPresent"] != false {
			t.Fatalf("Details[windowsServer2025DCPresent] = %v, want false", f.Details["windowsServer2025DCPresent"])
		}
	})

	t.Run("Windows Server 2025 DC present: Critical, as before", func(t *testing.T) {
		f := bsDetect(t, bsData(ace, bsIndex()))
		if f.Severity != types.SeverityCritical {
			t.Fatalf("severity = %q, want critical when a WS2025 DC makes the attack exploitable today", f.Severity)
		}
		if f.Details["cve"] != "CVE-2025-53779" {
			t.Fatalf("Details[cve] = %v, want CVE-2025-53779 (the prior CVE-2025-21293 attribution was wrong)", f.Details["cve"])
		}
	})
}

// TestBadSuccessorCVENotMisattributed pins the description text itself:
// CVE-2025-21293 is not BadSuccessor. This regression-tests the citation,
// not just the machine-readable Details field.
func TestBadSuccessorCVENotMisattributed(t *testing.T) {
	f := bsDetect(t, bsData([]types.ACLEntry{{
		ObjectDN:   bsOUDN,
		Trustee:    bsHelpdesk,
		AccessMask: 0x1,
		AceType:    "ACCESS_ALLOWED",
	}}, bsIndex()))
	if strings.Contains(f.Description, "CVE-2025-21293") {
		t.Fatalf("description still cites the wrong CVE (CVE-2025-21293); want CVE-2025-53779. Description: %q", f.Description)
	}
	if !strings.Contains(f.Description, "CVE-2025-53779") {
		t.Fatalf("description does not cite the correct CVE (CVE-2025-53779). Description: %q", f.Description)
	}
}
