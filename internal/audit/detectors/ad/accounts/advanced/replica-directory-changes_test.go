package advanced

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/providers/ldap"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const replicaDomainDN = "DC=contoso,DC=com"

// litGetChangesGUID / litGetChangesAllGUID are deliberately typed as plain
// string literals here, NOT as types.GUIDDSReplicationGetChanges[All]: a test
// that builds its fixture with the very same symbol the code under test reads
// can never catch a drift in either place (the two LAPS detectors survived
// months with a wrong types.GUIDLAPSPassword for exactly this structural
// reason - their tests compared against the same constant they built with).
// The values are the real Microsoft-documented extended-right GUIDs
// (learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes
// and .../r-ds-replication-get-changes-all), just not referenced via the
// code's symbol.
const (
	litGetChangesGUID    = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	litGetChangesAllGUID = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
)

func replicaTestUser(name, sid string, disabled bool) types.User {
	return types.User{
		SAMAccountName: name,
		DN:             "CN=" + name + ",CN=Users," + replicaDomainDN,
		ObjectSID:      sid,
		Disabled:       disabled,
	}
}

// encodeSIDForACE is the inverse of ldap's unexported parseSID: it turns a
// "S-<rev>-<auth>-<sub1>-...-<subN>" string into the MS-DTYP binary layout
// (revision, sub-authority count, 6-byte big-endian authority, N little-endian
// 32-bit sub-authorities), so a hand-built ACE can carry a real trustee SID
// through the real parser.
func encodeSIDForACE(t *testing.T, sid string) []byte {
	t.Helper()
	parts := strings.Split(sid, "-")
	if len(parts) < 4 || parts[0] != "S" {
		t.Fatalf("test setup: malformed SID %q", sid)
	}
	authority, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		t.Fatalf("test setup: bad SID authority in %q: %v", sid, err)
	}
	subAuthorities := parts[3:]

	buf := make([]byte, 8+4*len(subAuthorities))
	buf[0] = 0x01 // revision
	buf[1] = byte(len(subAuthorities))
	for i := 0; i < 6; i++ {
		buf[2+i] = byte(authority >> uint(8*(5-i)))
	}
	for i, sub := range subAuthorities {
		v, err := strconv.ParseUint(sub, 10, 32)
		if err != nil {
			t.Fatalf("test setup: bad SID sub-authority in %q: %v", sid, err)
		}
		binary.LittleEndian.PutUint32(buf[8+4*i:12+4*i], uint32(v))
	}
	return buf
}

// encodeMSGUIDForACE is the inverse of ldap's unexported parseGUID: it turns a
// canonical "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" GUID string into the
// mixed-endian 16-byte layout AD stores an ObjectType GUID in (Data1/2/3
// little-endian, Data4 as its 8 raw bytes), so a hand-built object ACE can
// name a real extended-right GUID through the real parser.
func encodeMSGUIDForACE(t *testing.T, guid string) []byte {
	t.Helper()
	parts := strings.Split(guid, "-")
	if len(parts) != 5 {
		t.Fatalf("test setup: malformed GUID %q", guid)
	}
	data1, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		t.Fatalf("test setup: bad GUID Data1 in %q: %v", guid, err)
	}
	data2, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		t.Fatalf("test setup: bad GUID Data2 in %q: %v", guid, err)
	}
	data3, err := strconv.ParseUint(parts[2], 16, 16)
	if err != nil {
		t.Fatalf("test setup: bad GUID Data3 in %q: %v", guid, err)
	}
	data4High, err := hex.DecodeString(parts[3])
	if err != nil || len(data4High) != 2 {
		t.Fatalf("test setup: bad GUID Data4 high in %q: %v", guid, err)
	}
	data4Low, err := hex.DecodeString(parts[4])
	if err != nil || len(data4Low) != 6 {
		t.Fatalf("test setup: bad GUID Data4 low in %q: %v", guid, err)
	}

	buf := make([]byte, 16)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(data1))
	binary.LittleEndian.PutUint16(buf[4:6], uint16(data2))
	binary.LittleEndian.PutUint16(buf[6:8], uint16(data3))
	copy(buf[8:10], data4High)
	copy(buf[10:16], data4Low)
	return buf
}

// buildObjectACEBytes hand-builds a single ACCESS_ALLOWED_OBJECT ACE
// (MS-DTYP 2.4.4.3): type(1)+flags(1)+size(2)+mask(4)+objectFlags(4)+
// ObjectType GUID(16)+SID(N), with ACE_OBJECT_TYPE_PRESENT set and no
// InheritedObjectType GUID - the exact shape an extended-right grant on the
// domain root takes on the wire.
func buildObjectACEBytes(t *testing.T, aceFlags byte, objectTypeGUID string, sid []byte) []byte {
	t.Helper()
	guidBytes := encodeMSGUIDForACE(t, objectTypeGUID)

	const aceObjectTypePresent = 0x01
	ace := make([]byte, 8+4+16+len(sid))
	ace[0] = 0x05 // AceType = ACCESS_ALLOWED_OBJECT
	ace[1] = aceFlags
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
	binary.LittleEndian.PutUint32(ace[4:8], uint32(types.MaskControlAccess))
	binary.LittleEndian.PutUint32(ace[8:12], aceObjectTypePresent)
	copy(ace[12:28], guidBytes)
	copy(ace[28:], sid)
	return ace
}

// buildSecurityDescriptorFromACEBytes wraps pre-built, fully-formed ACE byte
// slices (as buildObjectACEBytes produces) into a minimal, valid binary
// ntSecurityDescriptor (MS-DTYP 2.4.6) - the DACL/SD header plumbing shared by
// standard and object ACEs alike.
func buildSecurityDescriptorFromACEBytes(t *testing.T, aces ...[]byte) []byte {
	t.Helper()
	totalACEBytes := 0
	for _, a := range aces {
		totalACEBytes += len(a)
	}

	dacl := make([]byte, 8+totalACEBytes)
	dacl[0] = 0x04 // AclRevision
	binary.LittleEndian.PutUint16(dacl[2:4], uint16(len(dacl)))
	binary.LittleEndian.PutUint16(dacl[4:6], uint16(len(aces)))
	offset := 8
	for _, a := range aces {
		copy(dacl[offset:], a)
		offset += len(a)
	}

	const sdHeaderSize = 20
	sd := make([]byte, sdHeaderSize+len(dacl))
	sd[0] = 0x01                                   // Revision
	binary.LittleEndian.PutUint16(sd[2:4], 0x0004) // Control = SE_DACL_PRESENT
	binary.LittleEndian.PutUint32(sd[16:20], sdHeaderSize)
	copy(sd[sdHeaderSize:], dacl)
	return sd
}

// TestReplicaDirectoryChanges_BytesToDetector_InheritOnlyRoundTrip drives the
// real path bytes -> ldap.ParseSecurityDescriptor -> replicaRootHolders ->
// Detect. Every other test in this file builds types.ACLEntry values
// directly, so the parser itself (providers/ldap/acl_parser.go) and the
// detector are always exercised separately - a bit read at the wrong offset
// or the wrong mask in the real parser could still leave every test above
// green. This test supplies the one case that would expose that: the same
// pair of extended-right grants, once as an ordinary explicit ACE (must
// count) and once flagged INHERIT_ONLY (must not), pushed through the actual
// wire format.
func TestReplicaDirectoryChanges_BytesToDetector_InheritOnlyRoundTrip(t *testing.T) {
	const sidStr = "S-1-5-21-1-2-3-9016"
	sidBytes := encodeSIDForACE(t, sidStr)
	user := replicaTestUser("wire-format-holder", sidStr, false)

	explicitSD := buildSecurityDescriptorFromACEBytes(t,
		buildObjectACEBytes(t, 0x00, litGetChangesGUID, sidBytes),
		buildObjectACEBytes(t, 0x00, litGetChangesAllGUID, sidBytes),
	)
	explicitData := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users:      []types.User{user},
		ACLEntries: ldap.ParseSecurityDescriptor(explicitSD, replicaDomainDN),
	}
	explicitFindings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), explicitData)
	if explicitFindings[0].Count != 1 {
		t.Fatalf("AceFlags 0x00 (real parser): Count = %d, want 1 - both rights explicitly granted to the same trustee", explicitFindings[0].Count)
	}

	inheritOnlySD := buildSecurityDescriptorFromACEBytes(t,
		buildObjectACEBytes(t, 0x0a, litGetChangesGUID, sidBytes),
		buildObjectACEBytes(t, 0x0a, litGetChangesAllGUID, sidBytes),
	)
	inheritOnlyData := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users:      []types.User{user},
		ACLEntries: ldap.ParseSecurityDescriptor(inheritOnlySD, replicaDomainDN),
	}
	inheritOnlyFindings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), inheritOnlyData)
	if inheritOnlyFindings[0].Count != 0 {
		t.Fatalf("AceFlags 0x0a (real parser): Count = %d, want 0 - INHERIT_ONLY must be ignored end to end, not just at the types.ACLEntry level", inheritOnlyFindings[0].Count)
	}
}

// TestReplicaDirectoryChanges_OnlyGetChanges_NotCounted pins the central
// fix: holding DS-Replication-Get-Changes alone cannot run DCSync, so a
// trustee with only that right must not be flagged Critical.
func TestReplicaDirectoryChanges_OnlyGetChanges_NotCounted(t *testing.T) {
	sid := "S-1-5-21-1-2-3-9001"
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users:      []types.User{replicaTestUser("only-getchanges", sid, false)},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesGUID},
		},
	}
	findings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: DS-Replication-Get-Changes alone cannot run DCSync", findings[0].Count)
	}
}

// TestReplicaDirectoryChanges_OnlyGetChangesAll_NotCounted is the mirror of
// the above for the other half of the pair.
func TestReplicaDirectoryChanges_OnlyGetChangesAll_NotCounted(t *testing.T) {
	sid := "S-1-5-21-1-2-3-9002"
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users:      []types.User{replicaTestUser("only-getchangesall", sid, false)},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesAllGUID},
		},
	}
	findings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: DS-Replication-Get-Changes-All alone cannot run DCSync", findings[0].Count)
	}
}

// TestReplicaDirectoryChanges_BothRights_TwoSeparateACEs_Counted is the
// two-separate-ACEs shape - the common real-world case (a tool typically
// grants the pair as two ACEs, one per GUID).
func TestReplicaDirectoryChanges_BothRights_TwoSeparateACEs_Counted(t *testing.T) {
	sid := "S-1-5-21-1-2-3-9003"
	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: replicaDomainDN},
		Users:          []types.User{replicaTestUser("aadconnect", sid, false)},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesGUID},
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesAllGUID},
		},
	}
	findings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: non-admin user granted both rights via two separate ACEs", findings[0].Count)
	}
}

// TestReplicaDirectoryChanges_ControlAccessNoObjectType_Counted pins the
// AllExtendedRights equivalent: a CONTROL_ACCESS ACE with an empty
// ObjectType grants every extended right, replication rights included, even
// though it never names either GUID explicitly.
func TestReplicaDirectoryChanges_ControlAccessNoObjectType_Counted(t *testing.T) {
	sid := "S-1-5-21-1-2-3-9004"
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users:      []types.User{replicaTestUser("all-ext-rights", sid, false)},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: ""},
		},
	}
	findings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: CONTROL_ACCESS with no ObjectType grants every extended right, replication included", findings[0].Count)
	}
}

// TestReplicaDirectoryChanges_GenericAll_Counted pins the second equivalent:
// GenericAll subsumes CONTROL_ACCESS (and everything else), so it must count
// as holding both replication rights even without a CONTROL_ACCESS bit set.
func TestReplicaDirectoryChanges_GenericAll_Counted(t *testing.T) {
	sid := "S-1-5-21-1-2-3-9005"
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users:      []types.User{replicaTestUser("vuln-acl-test", sid, false)},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED", ObjectType: ""},
		},
	}
	findings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: GenericAll on the domain root subsumes both replication rights", findings[0].Count)
	}
}

// TestReplicaDirectoryChanges_ACEOnOtherObject_NotCounted guards the
// domain-root scope: an ACE granting both rights on any other object must
// not count. DCSync is only meaningful on the domain root/naming context.
func TestReplicaDirectoryChanges_ACEOnOtherObject_NotCounted(t *testing.T) {
	sid := "S-1-5-21-1-2-3-9006"
	otherDN := "CN=SomeOU," + replicaDomainDN
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users:      []types.User{replicaTestUser("wrong-object", sid, false)},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: otherDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesGUID},
			{ObjectDN: otherDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesAllGUID},
		},
	}
	findings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: ACE granted on an object other than the domain root must not count", findings[0].Count)
	}
}

// TestReplicaDirectoryChanges_UnresolvedTrusteeNotCounted guards the
// declared "population is users only" limitation: an ACE granting both
// rights to a SID that resolves to no entry in data.Users (a group or
// computer, in production) must not be counted - extending detection to
// those trustee types is explicitly out of scope for this ticket.
//
// data.Users deliberately holds one UNRELATED user at index 0, rather than
// being nil or empty: if the "trustee not in userBySID" guard is removed,
// held[sid] is still populated, and the final holders map does
// `holders[userBySID[sid]] = true` - a Go map miss on an int-valued map
// returns the zero value 0, so the removed guard would wrongly mark index 0
// as a holder. With Users nil or empty that indexes out of range and PANICS,
// which a test runner reports as a crash rather than a clean, informative
// assertion failure - exactly what happened when this guard was previously
// named M8. With a real, unrelated user at index 0, the same mutation
// instead makes Count wrongly become 1 and AffectedEntities wrongly name
// "unrelated-at-index-0", which the assertions below catch directly.
func TestReplicaDirectoryChanges_UnresolvedTrusteeNotCounted(t *testing.T) {
	sid := "S-1-5-21-1-2-3-9099"
	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: replicaDomainDN},
		Users: []types.User{
			replicaTestUser("unrelated-at-index-0", "S-1-5-21-1-2-3-0", false),
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesGUID},
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesAllGUID},
		},
	}
	findings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: trustee not present in data.Users (group/computer) is out of scope for this ticket", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 0 {
		t.Fatalf("AffectedEntities = %+v, want none: the unrelated user at index 0 must not be swept in", findings[0].AffectedEntities)
	}
}

// TestReplicaDirectoryChanges_DifferentTrustees_NotCumulated pins the fix for
// mutation M9: two DIFFERENT trustees, X holding only DS-Replication-Get-Changes
// and Y holding only DS-Replication-Get-Changes-All, must both count as 0 -
// the two rights must be held by the SAME trustee to count, not merely both
// present somewhere on the domain root across the whole population. A
// regression that tallied rights per-domain instead of per-trustee (e.g.
// "does ANY holder have GetChanges AND does ANY holder have GetChangesAll")
// would wrongly flag both X and Y here.
func TestReplicaDirectoryChanges_DifferentTrustees_NotCumulated(t *testing.T) {
	sidX := "S-1-5-21-1-2-3-9011"
	sidY := "S-1-5-21-1-2-3-9012"
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users: []types.User{
			replicaTestUser("m9-holder-x", sidX, false),
			replicaTestUser("m9-holder-y", sidY, false),
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: replicaDomainDN, Trustee: sidX, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesGUID},
			{ObjectDN: replicaDomainDN, Trustee: sidY, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesAllGUID},
		},
	}
	findings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: X holds Get-Changes alone, Y holds Get-Changes-All alone - neither individually can run DCSync", findings[0].Count)
	}

	disabledFindings := NewReplicaDirectoryChangesOnDisabledAccountDetector().Detect(context.Background(), data)
	if disabledFindings[0].Count != 0 {
		t.Fatalf("disabled Count = %d, want 0: same cross-trustee guard applies to the shared replicaRootHolders", disabledFindings[0].Count)
	}
}

// TestReplicaDirectoryChanges_InheritOnlyACE_NotCounted pins the core fix:
// an ACE flagged INHERIT_ONLY (AceFlags & 0x08) on the domain root does
// not apply to the root itself per MS-ADTS 3.1, so even a single ACE that
// would otherwise grant both rights at once (CONTROL_ACCESS with empty
// ObjectType) must not be counted when InheritOnly is set.
func TestReplicaDirectoryChanges_InheritOnlyACE_NotCounted(t *testing.T) {
	sid := "S-1-5-21-1-2-3-9013"
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users:      []types.User{replicaTestUser("inherit-only-holder", sid, false)},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: "", InheritOnly: true},
		},
	}
	findings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: an INHERIT_ONLY ACE on the domain root does not apply to the root itself (MS-ADTS 3.1)", findings[0].Count)
	}
}

// TestReplicaDirectoryChanges_InheritOnlyACE_NamedObjectType_NotCounted pins
// the InheritOnly guard against a narrower reading that only excludes ACEs
// with an empty ObjectType: an ACE flagged INHERIT_ONLY that ALSO names an
// extended-right GUID directly (as opposed to
// the "CONTROL_ACCESS with no ObjectType" equivalent already covered by
// TestReplicaDirectoryChanges_InheritOnlyACE_NotCounted) must still be
// ignored - MS-ADTS 3.1 does not carve out an exception for named rights.
func TestReplicaDirectoryChanges_InheritOnlyACE_NamedObjectType_NotCounted(t *testing.T) {
	sid := "S-1-5-21-1-2-3-9015"
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users:      []types.User{replicaTestUser("inherit-only-named-guid", sid, false)},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesGUID, InheritOnly: true},
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesAllGUID, InheritOnly: true},
		},
	}
	findings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: an INHERIT_ONLY ACE naming an extended right GUID directly still does not apply to the root itself (MS-ADTS 3.1) - the guard must not be narrowed to ACEs with an empty ObjectType", findings[0].Count)
	}
}

// TestReplicaDirectoryChangesOnDisabledAccount_InheritOnlyACE_NotCounted is
// the disabled-population mirror of the InheritOnly guard above, proving the
// fix holds for both keys since replicaRootHolders is shared.
func TestReplicaDirectoryChangesOnDisabledAccount_InheritOnlyACE_NotCounted(t *testing.T) {
	sid := "S-1-5-21-1-2-3-9014"
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users:      []types.User{replicaTestUser("inherit-only-holder-disabled", sid, true)},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED", ObjectType: "", InheritOnly: true},
		},
	}
	findings := NewReplicaDirectoryChangesOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: an INHERIT_ONLY ACE on the domain root does not apply to the root itself (MS-ADTS 3.1)", findings[0].Count)
	}
}

// TestReplicaDirectoryChanges_DomainAdminNotFlagged guards the baseline:
// Domain Admins hold this by default and must not be flagged, even when
// granted both rights explicitly.
func TestReplicaDirectoryChanges_DomainAdminNotFlagged(t *testing.T) {
	domainAdminSID := "S-1-5-21-1-2-3-512"
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users:      []types.User{replicaTestUser("corp-da", domainAdminSID, false)},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: replicaDomainDN, Trustee: domainAdminSID, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesGUID},
			{ObjectDN: replicaDomainDN, Trustee: domainAdminSID, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesAllGUID},
		},
	}
	findings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: Domain Admins are an expected baseline holder", findings[0].Count)
	}
}

// TestReplicaDirectoryChanges_KeywordAloneNotFlagged pins the removal of
// the old heuristic: an account whose description merely mentions
// "replication" (or a svc-prefixed name with adminCount) but holds no ACE
// at all must not fire - that was the exact source of unfounded findings.
func TestReplicaDirectoryChanges_KeywordAloneNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users: []types.User{
			{
				SAMAccountName: "svc-repl",
				ObjectSID:      "S-1-5-21-1-2-3-9007",
				Description:    "handles directory sync for the reporting tool",
				AdminCount:     true,
			},
		},
	}
	findings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: no ACE grants replication rights, keyword/name alone must not fire", findings[0].Count)
	}
}

// TestReplicaDirectoryChanges_DenyACENotCountedAsGrant documents the
// "Refus" half of the fix at its base case: a lone ACCESS_DENIED ACE naming
// both GUIDs is not itself a grant (audit.IsGrantACE rejects it) and must
// not count. NOTE - this does NOT test the harder case of an explicit deny
// coexisting with a separate ACCESS_ALLOWED grant elsewhere in the same
// DACL: that precedence is a declared, undhandled limitation (see the
// replicaRootHolders doc comment) because types.ACLEntry does not preserve
// DACL ordering.
func TestReplicaDirectoryChanges_DenyACENotCountedAsGrant(t *testing.T) {
	sid := "S-1-5-21-1-2-3-9008"
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users:      []types.User{replicaTestUser("denied-only", sid, false)},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_DENIED", ObjectType: litGetChangesGUID},
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_DENIED", ObjectType: litGetChangesAllGUID},
		},
	}
	findings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a deny ACE is never itself a grant", findings[0].Count)
	}
}

// TestReplicaDirectoryChanges_ActiveDisabledPartition runs BOTH detectors
// against a population of one active holder and one disabled holder: the
// active detector must report exactly the active one, the disabled
// detector exactly the disabled one - an exact partition, not an overlap
// or a gap.
func TestReplicaDirectoryChanges_ActiveDisabledPartition(t *testing.T) {
	activeSID := "S-1-5-21-1-2-3-9009"
	disabledSID := "S-1-5-21-1-2-3-9010"
	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: replicaDomainDN},
		Users: []types.User{
			replicaTestUser("active-holder", activeSID, false),
			replicaTestUser("disabled-holder", disabledSID, true),
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: replicaDomainDN, Trustee: activeSID, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesGUID},
			{ObjectDN: replicaDomainDN, Trustee: activeSID, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesAllGUID},
			{ObjectDN: replicaDomainDN, Trustee: disabledSID, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesGUID},
			{ObjectDN: replicaDomainDN, Trustee: disabledSID, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesAllGUID},
		},
	}

	activeFindings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)
	if activeFindings[0].Count != 1 {
		t.Fatalf("active Count = %d, want 1 (active-holder only)", activeFindings[0].Count)
	}
	if len(activeFindings[0].AffectedEntities) != 1 || activeFindings[0].AffectedEntities[0].SAMAccountName != "active-holder" {
		t.Fatalf("active AffectedEntities = %+v, want exactly active-holder", activeFindings[0].AffectedEntities)
	}

	disabledFindings := NewReplicaDirectoryChangesOnDisabledAccountDetector().Detect(context.Background(), data)
	if disabledFindings[0].Count != 1 {
		t.Fatalf("disabled Count = %d, want 1 (disabled-holder only)", disabledFindings[0].Count)
	}
	if len(disabledFindings[0].AffectedEntities) != 1 || disabledFindings[0].AffectedEntities[0].SAMAccountName != "disabled-holder" {
		t.Fatalf("disabled AffectedEntities = %+v, want exactly disabled-holder", disabledFindings[0].AffectedEntities)
	}
}

// TestReplicaDirectoryChanges_OutputOrderStable guards determinism: the
// previous version ranged over a Go map to build its output, which Go
// deliberately randomizes iteration order for. With five holders, two
// consecutive Detect() calls must produce the exact same DN order both
// times.
func TestReplicaDirectoryChanges_OutputOrderStable(t *testing.T) {
	data := &audit.DetectorData{IncludeDetails: true, DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN}}
	names := []string{"zulu", "alpha", "mike", "echo", "bravo"}
	for i, name := range names {
		sid := "S-1-5-21-1-2-3-92" + string(rune('0'+i))
		data.Users = append(data.Users, replicaTestUser(name, sid, false))
		data.ACLEntries = append(data.ACLEntries,
			types.ACLEntry{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesGUID},
			types.ACLEntry{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesAllGUID},
		)
	}

	first := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)
	second := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)

	if first[0].Count != len(names) || second[0].Count != len(names) {
		t.Fatalf("Count = %d/%d, want %d on both calls", first[0].Count, second[0].Count, len(names))
	}
	if len(first[0].AffectedEntities) != len(second[0].AffectedEntities) {
		t.Fatalf("AffectedEntities length differs between calls: %d vs %d", len(first[0].AffectedEntities), len(second[0].AffectedEntities))
	}
	for i := range first[0].AffectedEntities {
		dn1 := first[0].AffectedEntities[i].DN
		dn2 := second[0].AffectedEntities[i].DN
		if dn1 != dn2 {
			t.Fatalf("order differs at index %d: %q vs %q across two calls", i, dn1, dn2)
		}
		if i > 0 && first[0].AffectedEntities[i-1].DN > dn1 {
			t.Fatalf("output not sorted by DN: %q before %q", first[0].AffectedEntities[i-1].DN, dn1)
		}
	}
}

// TestReplicaDirectoryChanges_Severity pins Severity = Critical for the
// active-account detector.
func TestReplicaDirectoryChanges_Severity(t *testing.T) {
	findings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), &audit.DetectorData{DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN}})
	if findings[0].Severity != types.SeverityCritical {
		t.Fatalf("Severity = %q, want %q", findings[0].Severity, types.SeverityCritical)
	}
}

// TestReplicaDirectoryChanges_DescriptionLocked pins the exact Description
// text with a literal comparison, so a future edit that silently drifts the
// wording (or reverts to the old single-right claim) is caught immediately.
func TestReplicaDirectoryChanges_DescriptionLocked(t *testing.T) {
	const want = "Active accounts hold both the DS-Replication-Get-Changes and DS-Replication-Get-Changes-All extended rights - or an equivalent grant (GenericAll, or a CONTROL_ACCESS ACE with no ObjectType, which AD grants as every extended right) - on the domain root (Microsoft Learn, Win32 AD Schema reference, \"DS-Replication-Get-Changes[-All] extended right\"). Holding only one of the two rights cannot perform DCSync and is not reported. These accounts can extract all password hashes from the domain (DCSync). Limits: only user accounts are checked - computer accounts and groups holding the rights are not, and group membership is not expanded to the users inside; an ACE flagged inherit-only (applies only to descendants, not the domain root itself) is ignored; and an explicit ACCESS_DENIED ACE elsewhere in the same ACL is not evaluated against a separate grant."
	findings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), &audit.DetectorData{DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN}})
	if findings[0].Description != want {
		t.Fatalf("Description =\n%q\nwant\n%q", findings[0].Description, want)
	}
}
