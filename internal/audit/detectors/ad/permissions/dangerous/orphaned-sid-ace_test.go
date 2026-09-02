package dangerous

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// T_042 / B_020 — the real problem T_024/T_023 uncovered by accident: SID
// S-1-5-21-…-93801 resolves to no live object and holds full control on 293
// DC01 accounts. It was only ever surfaced by a BADSUCCESSOR_DMSA bug that
// T_023 correctly fixed — after the fix, nothing reported it. These two
// detectors are its dedicated replacement, split by whether the trustee's
// domain prefix is ours (likely a deleted account) or foreign (a reference we
// cannot verify locally).

const (
	orphDomainSID = "S-1-5-21-1234567890-1111111111-2222222222"
	orphDomainDN  = "DC=example,DC=com"
	orphUserDN    = "CN=Guest,CN=Users," + orphDomainDN

	orphLocalUnresolvedSID   = orphDomainSID + "-93801"
	orphForeignUnresolvedSID = "S-1-5-21-9999999999-8888888888-7777777777-500"
	orphKnownUserSID         = orphDomainSID + "-1105"

	orphMaskFullControl = 0x000F01FF
	orphMaskReadOnly    = 0x00000020 // ReadProperty — not dangerous
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
// deleted account — it falls to the cross-domain, "cannot verify" bucket.
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
// false positive the ticket warns against: a SID the engine CAN name (present
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

// TestOrphanedSidDangerousACE_WellKnownSIDNeverFires — a well-known SID
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

// TestOrphanedSidDangerousACE_BuiltinAdminNeverFires mirrors the T_024 guard
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

// TestOrphanedSidDangerousACE_NonDangerousRightDoesNotFire — an unresolved
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

// TestOrphanedSidDangerousACE_DenyACEDoesNotFire — DET_10: a DENY ace grants
// nothing.
func TestOrphanedSidDangerousACE_DenyACEDoesNotFire(t *testing.T) {
	data := orphData(orphDomainSID,
		types.ACLEntry{ObjectDN: orphUserDN, Trustee: orphLocalUnresolvedSID, AccessMask: orphMaskFullControl, AceType: "ACCESS_DENIED"},
	)
	if f := detectOrphan(t, NewOrphanedSidDangerousACEDetector(), data); f.Count != 0 {
		t.Errorf("a DENY ace must not fire, count=%d", f.Count)
	}
}

// TestOrphanedSidDangerousACE_CountsUniqueAccountsNotACEs — the same orphan
// SID holding multiple dangerous rights on the same account (as observed on
// DC01: the 293 accounts carry GenericAll AND WriteDACL AND WriteOwner from
// the same trustee) must count as ONE account, not one per ACE — same lesson
// T_023 already applied to BADSUCCESSOR_DMSA.
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
