package dangerous

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// T_024 — ACL_WRITEDACL / ACL_WRITEOWNER / ACL_GENERICALL / ACL_SELF_MEMBERSHIP
// each fired on 1167 of 1167 objects on DC01 with byte-identical entity sets,
// because AD's own SYSTEM / Domain Admins / BUILTIN\Administrators full-control
// ACEs were counted as findings. Each test below pairs the suppressed false
// positive with the true positive that must still fire.

const (
	aclDomainDN = "DC=example,DC=com"
	aclDomain   = "S-1-5-21-1234567890-1111111111-2222222222"
	aclUserDN   = "CN=Akira Jackson,OU=IT," + aclDomainDN
	aclGroupDN  = "CN=Helpdesk,OU=IT," + aclDomainDN

	sidSystem       = "S-1-5-18"
	sidBuiltinAdmin = "S-1-5-32-544"
	sidDomainAdmins = aclDomain + "-512"
	// An ordinary domain principal — on DC01 this is the shape of the
	// unresolvable SID that holds full control on 293 accounts.
	sidOrdinary = aclDomain + "-93801"

	maskWriteDACL     = 0x00040000
	maskWriteOwner    = 0x00080000
	maskFullControl   = 0x000F01FF
	maskWriteSelf     = 0x8
	maskControlAccess = 0x00000100

	guidSelfMembership = "bf9679c0-0de6-11d0-a285-00aa003049e2"
	guidReplicationGet = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	guidReplicationAll = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

	sidDomainControllers = aclDomain + "-516"
	sidEnterpriseDCs     = "S-1-5-9"
)

// aclData wires ACEs plus the DN-indexed cache detectors read object classes
// from (the engine builds it in collectData).
func aclData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		ObjectByDN: map[string]*audit.ObjectMeta{
			aclUserDN:   {DN: aclUserDN, Name: "Akira Jackson", EntityType: types.EntityTypeUser},
			aclGroupDN:  {DN: aclGroupDN, Name: "Helpdesk", EntityType: types.EntityTypeGroup},
			aclDomainDN: {DN: aclDomainDN, Name: "example", EntityType: types.EntityTypeDomain},
		},
	}
}

func detectOne(t *testing.T, d audit.Detector, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("%s: expected exactly 1 finding, got %d", d.ID(), len(findings))
	}
	return findings[0]
}

// TestDangerousACL_SkipsBuiltinAdminTrustees covers acceptance §2.
func TestDangerousACL_SkipsBuiltinAdminTrustees(t *testing.T) {
	detectors := []struct {
		name string
		make func() audit.Detector
		mask int
	}{
		{"ACL_WRITEDACL", func() audit.Detector { return NewWriteDACLDetector() }, maskWriteDACL},
		{"ACL_WRITEOWNER", func() audit.Detector { return NewWriteOwnerDetector() }, maskWriteOwner},
		{"ACL_GENERICALL", func() audit.Detector { return NewGenericAllDetector() }, maskFullControl},
	}

	for _, d := range detectors {
		t.Run(d.name+"/builtin admins do NOT fire", func(t *testing.T) {
			// The three ACEs Active Directory puts on every object.
			f := detectOne(t, d.make(), aclData(
				types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidSystem, AccessMask: maskFullControl, AceType: "ACCESS_ALLOWED"},
				types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidDomainAdmins, AccessMask: maskFullControl, AceType: "ACCESS_ALLOWED"},
				types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidBuiltinAdmin, AccessMask: maskFullControl, AceType: "ACCESS_ALLOWED"},
			))
			if f.Count != 0 {
				t.Fatalf("AD's own baseline ACEs must not be findings, got count=%d", f.Count)
			}
		})

		t.Run(d.name+"/ordinary domain principal DOES fire", func(t *testing.T) {
			f := detectOne(t, d.make(), aclData(
				types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: d.mask, AceType: "ACCESS_ALLOWED"},
			))
			if f.Count != 1 {
				t.Fatalf("a domain principal holding the right must fire, got count=%d", f.Count)
			}
			if len(f.AffectedEntities) != 1 {
				t.Fatalf("finding must be actionable, got %d entities", len(f.AffectedEntities))
			}
			if f.Severity != types.SeverityHigh {
				t.Errorf("severity = %q, want high", f.Severity)
			}
		})
	}
}

// TestSelfMembership_RequiresGroupTarget covers acceptance §2: self-membership
// is only meaningful on a group. It previously claimed the right over 546
// users, 352 OUs and the domain root.
func TestSelfMembership_RequiresGroupTarget(t *testing.T) {
	t.Run("user target does NOT fire", func(t *testing.T) {
		f := detectOne(t, NewSelfMembershipDetector(), aclData(
			types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: maskWriteSelf, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("you cannot add yourself to a user object, got count=%d", f.Count)
		}
	})

	t.Run("domain root does NOT fire", func(t *testing.T) {
		f := detectOne(t, NewSelfMembershipDetector(), aclData(
			types.ACLEntry{ObjectDN: aclDomainDN, Trustee: sidOrdinary, AccessMask: maskFullControl, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("the domain root is not a group, got count=%d", f.Count)
		}
	})

	t.Run("Self-Membership right on a GROUP DOES fire", func(t *testing.T) {
		f := detectOne(t, NewSelfMembershipDetector(), aclData(
			types.ACLEntry{ObjectDN: aclGroupDN, Trustee: sidOrdinary, AccessMask: maskWriteSelf, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: guidSelfMembership},
		))
		if f.Count != 1 {
			t.Fatalf("Self-Membership on a group is the real finding, got count=%d", f.Count)
		}
		if len(f.AffectedEntities) != 1 {
			t.Fatalf("finding must be actionable, got %d entities", len(f.AffectedEntities))
		}
	})

	t.Run("unscoped validated write on a GROUP DOES fire", func(t *testing.T) {
		f := detectOne(t, NewSelfMembershipDetector(), aclData(
			types.ACLEntry{ObjectDN: aclGroupDN, Trustee: sidOrdinary, AccessMask: maskWriteSelf, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("DS_SELF with no ObjectType on a group must fire, got count=%d", f.Count)
		}
	})

	t.Run("a GUID merely containing 'member' does NOT fire", func(t *testing.T) {
		// The removed predicate was strings.Contains(ObjectType, "member") —
		// a substring test against a GUID.
		f := detectOne(t, NewSelfMembershipDetector(), aclData(
			types.ACLEntry{ObjectDN: aclGroupDN, Trustee: sidOrdinary, AccessMask: 0x10, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: "membe12b-0de6-11d0-a285-00aa003049e2"},
		))
		if f.Count != 0 {
			t.Fatalf("a substring match on a GUID is not a right, got count=%d", f.Count)
		}
	})
}

// TestDenyACEsAreNotGrants covers acceptance §3 (DET_10).
func TestDenyACEsAreNotGrants(t *testing.T) {
	cases := []struct {
		name    string
		make    func() audit.Detector
		ace     types.ACLEntry
		wantPos bool
	}{
		{"WRITEDACL/deny", func() audit.Detector { return NewWriteDACLDetector() },
			types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: maskWriteDACL, AceType: "ACCESS_DENIED"}, false},
		{"WRITEDACL/deny object", func() audit.Detector { return NewWriteDACLDetector() },
			types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: maskWriteDACL, AceType: "ACCESS_DENIED_OBJECT"}, false},
		{"WRITEDACL/allow still fires", func() audit.Detector { return NewWriteDACLDetector() },
			types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: maskWriteDACL, AceType: "ACCESS_ALLOWED"}, true},
		{"WRITEOWNER/deny", func() audit.Detector { return NewWriteOwnerDetector() },
			types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: maskWriteOwner, AceType: "ACCESS_DENIED"}, false},
		{"GENERICALL/deny", func() audit.Detector { return NewGenericAllDetector() },
			types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: maskFullControl, AceType: "ACCESS_DENIED"}, false},
		{"SELF_MEMBERSHIP/deny", func() audit.Detector { return NewSelfMembershipDetector() },
			types.ACLEntry{ObjectDN: aclGroupDN, Trustee: sidOrdinary, AccessMask: maskWriteSelf, AceType: "ACCESS_DENIED"}, false},
		{"GENERICALL/audit ace", func() audit.Detector { return NewGenericAllDetector() },
			types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: maskFullControl, AceType: "SYSTEM_AUDIT"}, false},
		{"DCSYNC/deny", func() audit.Detector { return NewDCSyncDetector() },
			types.ACLEntry{ObjectDN: aclDomainDN, Trustee: sidOrdinary, AccessMask: maskControlAccess, AceType: "ACCESS_DENIED_OBJECT", ObjectType: guidReplicationGet}, false},
		{"DCSYNC/allow still fires", func() audit.Detector { return NewDCSyncDetector() },
			types.ACLEntry{ObjectDN: aclDomainDN, Trustee: sidOrdinary, AccessMask: maskControlAccess, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: guidReplicationGet}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := detectOne(t, tc.make(), aclData(tc.ace))
			want := 0
			if tc.wantPos {
				want = 1
			}
			if f.Count != want {
				t.Fatalf("count = %d, want %d (a DENY ace grants nothing)", f.Count, want)
			}
		})
	}
}

// TestDCSync covers T_065/B_172: ACL_DS_REPLICATION_GET_CHANGES matched on
// ObjectType alone, so it flagged AD's own baseline replication grants
// (BUILTIN\Administrators, Domain Controllers, Enterprise Domain
// Controllers — reproduced live on DC01) as "non-standard principals" on
// every domain, healthy or not. It also never read AccessMask, so an
// ObjectType match with no CONTROL_ACCESS bit at all would have fired.
func TestDCSync(t *testing.T) {
	t.Run("AD's own baseline replication grants do NOT fire", func(t *testing.T) {
		// The exact three trustees security reproduced on DC01 (CHECKS.yml).
		f := detectOne(t, NewDCSyncDetector(), aclData(
			types.ACLEntry{ObjectDN: aclDomainDN, Trustee: sidBuiltinAdmin, AccessMask: maskControlAccess, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: guidReplicationGet},
			types.ACLEntry{ObjectDN: aclDomainDN, Trustee: sidBuiltinAdmin, AccessMask: maskControlAccess, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: guidReplicationAll},
			types.ACLEntry{ObjectDN: aclDomainDN, Trustee: sidDomainControllers, AccessMask: maskControlAccess, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: guidReplicationAll},
			types.ACLEntry{ObjectDN: aclDomainDN, Trustee: sidEnterpriseDCs, AccessMask: maskControlAccess, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: guidReplicationGet},
		))
		if f.Count != 0 {
			t.Fatalf("AD's own baseline replication grants must not be findings, got count=%d", f.Count)
		}
	})

	t.Run("an ordinary domain principal with real replication rights DOES fire", func(t *testing.T) {
		f := detectOne(t, NewDCSyncDetector(), aclData(
			types.ACLEntry{ObjectDN: aclDomainDN, Trustee: sidOrdinary, AccessMask: maskControlAccess, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: guidReplicationAll},
		))
		if f.Count != 1 {
			t.Fatalf("a domain principal actually granted DCSync must fire, got count=%d", f.Count)
		}
		if len(f.AffectedEntities) != 1 {
			t.Fatalf("finding must be actionable, got %d entities", len(f.AffectedEntities))
		}
		if f.Severity != types.SeverityCritical {
			t.Errorf("severity = %q, want critical", f.Severity)
		}
	})

	t.Run("both replication GUIDs are recognised", func(t *testing.T) {
		for _, guid := range []string{guidReplicationGet, guidReplicationAll} {
			f := detectOne(t, NewDCSyncDetector(), aclData(
				types.ACLEntry{ObjectDN: aclDomainDN, Trustee: sidOrdinary, AccessMask: maskControlAccess, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: guid},
			))
			if f.Count != 1 {
				t.Fatalf("GUID %s must fire, got count=%d", guid, f.Count)
			}
		}
	})

	t.Run("ObjectType match without CONTROL_ACCESS does NOT fire", func(t *testing.T) {
		// T_065/B_172: the detector matched on ObjectType alone and never read
		// AccessMask at all — this ACE would previously have counted.
		f := detectOne(t, NewDCSyncDetector(), aclData(
			types.ACLEntry{ObjectDN: aclDomainDN, Trustee: sidOrdinary, AccessMask: 0, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: guidReplicationGet},
		))
		if f.Count != 0 {
			t.Fatalf("ObjectType without the CONTROL_ACCESS bit is not a grant, got count=%d", f.Count)
		}
	})

	t.Run("an unrelated ObjectType GUID does NOT fire", func(t *testing.T) {
		f := detectOne(t, NewDCSyncDetector(), aclData(
			types.ACLEntry{ObjectDN: aclDomainDN, Trustee: sidOrdinary, AccessMask: maskControlAccess, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: guidSelfMembership},
		))
		if f.Count != 0 {
			t.Fatalf("an unrelated extended right must not fire as DCSync, got count=%d", f.Count)
		}
	})
}

// TestEnterpriseKeyAdmins covers T_088/B_185: a real GenericAll grant to
// Enterprise Key Admins on the domain root — planted live on DC01 via
// check-runner.sh, confirmed present via dsacls, and confirmed CONFIRMED
// afterwards by the same runner — was invisible to this detector because it
// only tested the raw GENERIC_ALL bit (0x10000000). dsacls /G ... GA writes
// the AD-mapped full-control form (0x000F01FF) instead, exactly the
// distinction ACL_GENERICALL (in this same package) already handles.
func TestEnterpriseKeyAdmins(t *testing.T) {
	enterpriseKeyAdminsSID := aclDomain + "-527"

	t.Run("mapped full-control form (what dsacls GA actually writes) DOES fire", func(t *testing.T) {
		f := detectOne(t, NewEnterpriseKeyAdminsDetector(), aclData(
			types.ACLEntry{ObjectDN: aclDomainDN, Trustee: enterpriseKeyAdminsSID, AccessMask: maskFullControl, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("Enterprise Key Admins holding the AD-mapped full-control mask must fire, got count=%d", f.Count)
		}
	})

	t.Run("raw GENERIC_ALL bit still fires", func(t *testing.T) {
		f := detectOne(t, NewEnterpriseKeyAdminsDetector(), aclData(
			types.ACLEntry{ObjectDN: aclDomainDN, Trustee: enterpriseKeyAdminsSID, AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("the raw GENERIC_ALL bit must still fire, got count=%d", f.Count)
		}
	})

	t.Run("msDS-KeyCredentialLink WriteProperty still fires", func(t *testing.T) {
		f := detectOne(t, NewEnterpriseKeyAdminsDetector(), aclData(
			types.ACLEntry{ObjectDN: aclDomainDN, Trustee: enterpriseKeyAdminsSID, AccessMask: types.MaskWriteProperty, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: "5b47d60f-6090-40b2-9f37-2a4de88f3063"},
		))
		if f.Count != 1 {
			t.Fatalf("WriteProperty on msDS-KeyCredentialLink must fire, got count=%d", f.Count)
		}
	})

	t.Run("a trustee not ending in -527 does NOT fire", func(t *testing.T) {
		f := detectOne(t, NewEnterpriseKeyAdminsDetector(), aclData(
			types.ACLEntry{ObjectDN: aclDomainDN, Trustee: sidOrdinary, AccessMask: maskFullControl, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("an ordinary trustee must not fire, got count=%d", f.Count)
		}
	})
}
