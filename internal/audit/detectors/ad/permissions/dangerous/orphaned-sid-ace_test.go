package dangerous

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Covers ORPHANED_SID_DANGEROUS_ACE and CROSS_DOMAIN_SID_DANGEROUS_ACE, split
// by whether an unresolved trustee's domain prefix is ours (likely a deleted
// account) or foreign (a reference that cannot be verified locally).

const (
	orphDomainSID = "S-1-5-21-1234567890-1111111111-2222222222"
	orphDomainDN  = "DC=example,DC=com"
	orphUserDN    = "CN=Guest,CN=Users," + orphDomainDN

	orphLocalUnresolvedSID   = orphDomainSID + "-93801"
	orphLocalUnresolvedSID2  = orphDomainSID + "-93802"
	orphForeignUnresolvedSID = "S-1-5-21-9999999999-8888888888-7777777777-500"
	orphKnownUserSID         = orphDomainSID + "-1105"

	orphMaskFullControl  = 0x000F01FF
	orphMaskReadOnly     = 0x00000020 // ReadProperty - not dangerous
	orphMaskGenericAll   = 0x10000000
	orphMaskReadProperty = 0x00000010
)

func orphData(domainSID string, aces ...types.ACLEntry) *audit.DetectorData {
	d := &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		ObjectByDN: map[string]*audit.ObjectMeta{
			orphUserDN: {DN: orphUserDN, SAMAccountName: "Guest", Name: "Guest", EntityType: types.EntityTypeUser, SID: orphKnownUserSID},
		},
	}
	d.ObjectBySID = map[string]*audit.ObjectMeta{orphKnownUserSID: d.ObjectByDN[orphUserDN]}
	if domainSID != "" {
		d.DomainInfo = &types.DomainInfo{DomainDN: orphDomainDN, DomainSID: domainSID}
	}
	return d
}

func detectOrphan(t *testing.T, d audit.Detector, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("%s: expected exactly 1 finding, got %d", d.ID(), len(findings))
	}
	return findings[0]
}

// TestOrphanedSidDangerousACE_LocalDomainUnresolvedSIDFires covers acceptance
// §3: a domain-local SID with no matching object and a dangerous right must
// fire ORPHANED_SID_DANGEROUS_ACE, and NOT CrossDomain.
func TestOrphanedSidDangerousACE_LocalDomainUnresolvedSIDFires(t *testing.T) {
	data := orphData(orphDomainSID,
		types.ACLEntry{ObjectDN: orphUserDN, Trustee: orphLocalUnresolvedSID, AccessMask: orphMaskFullControl, AceType: "ACCESS_ALLOWED"},
	)

	local := detectOrphan(t, NewOrphanedSidDangerousACEDetector(), data)
	if local.Count != 1 {
		t.Fatalf("local-domain unresolved SID with a dangerous right must fire, count=%d", local.Count)
	}
	if local.Severity != types.SeverityHigh {
		t.Errorf("severity = %q, want high", local.Severity)
	}
	if len(local.AffectedEntities) != 1 || local.AffectedEntities[0].DN != orphUserDN {
		t.Errorf("affected entity wrong: %+v", local.AffectedEntities)
	}

	foreign := detectOrphan(t, NewCrossDomainSidDangerousACEDetector(), data)
	if foreign.Count != 0 {
		t.Errorf("a local-domain SID must not also fire CROSS_DOMAIN_SID_DANGEROUS_ACE, count=%d", foreign.Count)
	}
}

// TestCrossDomainSidDangerousACE_ForeignSIDFires covers acceptance §3/§5: a
// SID whose domain prefix does not match ours fires the cross-domain
// detector instead, at a higher severity.
func TestCrossDomainSidDangerousACE_ForeignSIDFires(t *testing.T) {
	data := orphData(orphDomainSID,
		types.ACLEntry{ObjectDN: orphUserDN, Trustee: orphForeignUnresolvedSID, AccessMask: orphMaskFullControl, AceType: "ACCESS_ALLOWED"},
	)

	foreign := detectOrphan(t, NewCrossDomainSidDangerousACEDetector(), data)
	if foreign.Count != 1 {
		t.Fatalf("foreign-domain unresolved SID with a dangerous right must fire, count=%d", foreign.Count)
	}
	if foreign.Severity != types.SeverityCritical {
		t.Errorf("severity = %q, want critical", foreign.Severity)
	}

	local := detectOrphan(t, NewOrphanedSidDangerousACEDetector(), data)
	if local.Count != 0 {
		t.Errorf("a foreign-domain SID must not also fire ORPHANED_SID_DANGEROUS_ACE, count=%d", local.Count)
	}
}

// TestOrphanedSidDangerousACE_UnknownDomainSIDFallsClosedToForeign covers the
// F.1 fail-closed case: without data.DomainInfo.DomainSID we cannot tell
// "ours" from "foreign", so an unresolved SID must NOT be claimed as a local
// deleted account - it falls to the cross-domain, "cannot verify" bucket.
func TestOrphanedSidDangerousACE_UnknownDomainSIDFallsClosedToForeign(t *testing.T) {
	data := orphData("", // no DomainInfo.DomainSID
		types.ACLEntry{ObjectDN: orphUserDN, Trustee: orphLocalUnresolvedSID, AccessMask: orphMaskFullControl, AceType: "ACCESS_ALLOWED"},
	)

	local := detectOrphan(t, NewOrphanedSidDangerousACEDetector(), data)
	if local.Count != 0 {
		t.Errorf("without a known domain SID, must not claim a local deleted account, count=%d", local.Count)
	}
	foreign := detectOrphan(t, NewCrossDomainSidDangerousACEDetector(), data)
	if foreign.Count != 1 {
		t.Errorf("without a known domain SID, an unresolved trustee falls to the unverifiable bucket, count=%d", foreign.Count)
	}
}

// TestOrphanedSidDangerousACE_ResolvedTrusteeNeverFires covers the symmetric
// false positive this warns against: a SID the engine CAN name (present
// in ObjectBySID) is not an orphan, regardless of domain prefix.
func TestOrphanedSidDangerousACE_ResolvedTrusteeNeverFires(t *testing.T) {
	data := orphData(orphDomainSID,
		types.ACLEntry{ObjectDN: orphUserDN, Trustee: orphKnownUserSID, AccessMask: orphMaskFullControl, AceType: "ACCESS_ALLOWED"},
	)
	if f := detectOrphan(t, NewOrphanedSidDangerousACEDetector(), data); f.Count != 0 {
		t.Errorf("a resolvable trustee must not fire ORPHANED_SID_DANGEROUS_ACE, count=%d", f.Count)
	}
	if f := detectOrphan(t, NewCrossDomainSidDangerousACEDetector(), data); f.Count != 0 {
		t.Errorf("a resolvable trustee must not fire CROSS_DOMAIN_SID_DANGEROUS_ACE, count=%d", f.Count)
	}
}

// TestOrphanedSidDangerousACE_WellKnownSIDNeverFires - a well-known SID
// (e.g. Everyone) is "unresolved" via ObjectBySID but IS named via the static
// table; it must not be treated as an orphan.
func TestOrphanedSidDangerousACE_WellKnownSIDNeverFires(t *testing.T) {
	data := orphData(orphDomainSID,
		types.ACLEntry{ObjectDN: orphUserDN, Trustee: "S-1-1-0", AccessMask: orphMaskFullControl, AceType: "ACCESS_ALLOWED"},
	)
	if f := detectOrphan(t, NewOrphanedSidDangerousACEDetector(), data); f.Count != 0 {
		t.Errorf("a well-known SID must not fire ORPHANED_SID_DANGEROUS_ACE, count=%d", f.Count)
	}
	if f := detectOrphan(t, NewCrossDomainSidDangerousACEDetector(), data); f.Count != 0 {
		t.Errorf("a well-known SID must not fire CROSS_DOMAIN_SID_DANGEROUS_ACE, count=%d", f.Count)
	}
}

// TestOrphanedSidDangerousACE_BuiltinAdminNeverFires mirrors the same guard
// already proven for ACL_GENERICALL/WRITEDACL/WRITEOWNER: SYSTEM/Domain
// Admins/BUILTIN\Administrators are excluded even though they'd otherwise
// look domain-local-unresolved in a minimal test fixture.
func TestOrphanedSidDangerousACE_BuiltinAdminNeverFires(t *testing.T) {
	data := orphData(orphDomainSID,
		types.ACLEntry{ObjectDN: orphUserDN, Trustee: "S-1-5-18", AccessMask: orphMaskFullControl, AceType: "ACCESS_ALLOWED"},
		types.ACLEntry{ObjectDN: orphUserDN, Trustee: orphDomainSID + "-512", AccessMask: orphMaskFullControl, AceType: "ACCESS_ALLOWED"},
	)
	if f := detectOrphan(t, NewOrphanedSidDangerousACEDetector(), data); f.Count != 0 {
		t.Errorf("builtin admin trustees must not fire, count=%d", f.Count)
	}
}

// TestOrphanedSidDangerousACE_NonDangerousRightDoesNotFire - an unresolved
// trustee holding an unremarkable right (ReadProperty) is not this detector's
// concern.
func TestOrphanedSidDangerousACE_NonDangerousRightDoesNotFire(t *testing.T) {
	data := orphData(orphDomainSID,
		types.ACLEntry{ObjectDN: orphUserDN, Trustee: orphLocalUnresolvedSID, AccessMask: orphMaskReadOnly, AceType: "ACCESS_ALLOWED"},
	)
	if f := detectOrphan(t, NewOrphanedSidDangerousACEDetector(), data); f.Count != 0 {
		t.Errorf("a non-dangerous right must not fire, count=%d", f.Count)
	}
}

// TestOrphanedSidDangerousACE_DenyACEDoesNotFire - a DENY ace grants nothing.
func TestOrphanedSidDangerousACE_DenyACEDoesNotFire(t *testing.T) {
	data := orphData(orphDomainSID,
		types.ACLEntry{ObjectDN: orphUserDN, Trustee: orphLocalUnresolvedSID, AccessMask: orphMaskFullControl, AceType: "ACCESS_DENIED"},
	)
	if f := detectOrphan(t, NewOrphanedSidDangerousACEDetector(), data); f.Count != 0 {
		t.Errorf("a DENY ace must not fire, count=%d", f.Count)
	}
}

// TestOrphanedSidDangerousACE_CountsUniqueAccountsNotACEs - the same orphan
// SID holding multiple dangerous rights on the same account must count as
// ONE account, not one per ACE.
func TestOrphanedSidDangerousACE_CountsUniqueAccountsNotACEs(t *testing.T) {
	data := orphData(orphDomainSID,
		types.ACLEntry{ObjectDN: orphUserDN, Trustee: orphLocalUnresolvedSID, AccessMask: 0x10000000, AceType: "ACCESS_ALLOWED"}, // GenericAll
		types.ACLEntry{ObjectDN: orphUserDN, Trustee: orphLocalUnresolvedSID, AccessMask: 0x00040000, AceType: "ACCESS_ALLOWED"}, // WriteDACL
		types.ACLEntry{ObjectDN: orphUserDN, Trustee: orphLocalUnresolvedSID, AccessMask: 0x00080000, AceType: "ACCESS_ALLOWED"}, // WriteOwner
	)
	f := detectOrphan(t, NewOrphanedSidDangerousACEDetector(), data)
	if f.Count != 1 {
		t.Fatalf("3 ACEs on 1 account must count as 1, got %d", f.Count)
	}
	if f.TotalInstances != 3 {
		t.Errorf("totalInstances should record the 3 underlying ACEs, got %d", f.TotalInstances)
	}
}

// TestOrphanedSidDangerousACE_LabPlantWitnesses mirrors a live lab plant of
// 4 OUs that proved each filter against a real domain, one ACE per OU so
// dedup-by-DN cannot mask one witness behind another:
//   - t522a: local-domain orphan RID + GenericAll -> fires ORPHANED, alone.
//   - t522b: GenericAll but a RESOLVABLE trustee -> does not fire (filter 4).
//   - t522c: local-domain orphan RID but ReadProperty only -> does not fire
//     (filter 2, dangerous-rights).
//   - t522d: foreign-domain orphan + GenericAll -> fires CROSS_DOMAIN
//     instead of ORPHANED (filter 5, local-domain).
func TestOrphanedSidDangerousACE_LabPlantWitnesses(t *testing.T) {
	const (
		dnA = "OU=t522a,OU=T522PlantsFixture," + orphDomainDN
		dnB = "OU=t522b,OU=T522PlantsFixture," + orphDomainDN
		dnC = "OU=t522c,OU=T522PlantsFixture," + orphDomainDN
		dnD = "OU=t522d,OU=T522PlantsFixture," + orphDomainDN
	)
	data := orphData(orphDomainSID,
		types.ACLEntry{ObjectDN: dnA, Trustee: orphLocalUnresolvedSID, AccessMask: orphMaskGenericAll, AceType: "ACCESS_ALLOWED"},
		types.ACLEntry{ObjectDN: dnB, Trustee: orphKnownUserSID, AccessMask: orphMaskGenericAll, AceType: "ACCESS_ALLOWED"},
		types.ACLEntry{ObjectDN: dnC, Trustee: orphLocalUnresolvedSID2, AccessMask: orphMaskReadProperty, AceType: "ACCESS_ALLOWED"},
		types.ACLEntry{ObjectDN: dnD, Trustee: orphForeignUnresolvedSID, AccessMask: orphMaskGenericAll, AceType: "ACCESS_ALLOWED"},
	)

	hasDN := func(entities []types.AffectedEntity, dn string) bool {
		for _, e := range entities {
			if e.DN == dn {
				return true
			}
		}
		return false
	}

	t.Run("t522a_local_orphan_generic_all_fires_alone", func(t *testing.T) {
		local := detectOrphan(t, NewOrphanedSidDangerousACEDetector(), data)
		if local.Count != 1 {
			t.Fatalf("expected exactly 1 (t522a only), got Count=%d", local.Count)
		}
		if !hasDN(local.AffectedEntities, dnA) {
			t.Errorf("t522a must be the fired DN, got %+v", local.AffectedEntities)
		}
	})
	t.Run("t522b_resolvable_trustee_does_not_fire", func(t *testing.T) {
		local := detectOrphan(t, NewOrphanedSidDangerousACEDetector(), data)
		if hasDN(local.AffectedEntities, dnB) {
			t.Errorf("t522b (resolvable trustee) must not fire ORPHANED_SID_DANGEROUS_ACE")
		}
	})
	t.Run("t522c_nondangerous_right_does_not_fire", func(t *testing.T) {
		local := detectOrphan(t, NewOrphanedSidDangerousACEDetector(), data)
		if hasDN(local.AffectedEntities, dnC) {
			t.Errorf("t522c (ReadProperty only) must not fire ORPHANED_SID_DANGEROUS_ACE")
		}
	})
	t.Run("t522d_foreign_fires_cross_domain_not_orphaned", func(t *testing.T) {
		local := detectOrphan(t, NewOrphanedSidDangerousACEDetector(), data)
		if hasDN(local.AffectedEntities, dnD) {
			t.Errorf("t522d (foreign-domain SID) must not fire ORPHANED_SID_DANGEROUS_ACE")
		}
		foreign := detectOrphan(t, NewCrossDomainSidDangerousACEDetector(), data)
		if foreign.Count != 1 || !hasDN(foreign.AffectedEntities, dnD) {
			t.Errorf("t522d must fire CROSS_DOMAIN_SID_DANGEROUS_ACE instead, got Count=%d entities=%+v", foreign.Count, foreign.AffectedEntities)
		}
	})
}
