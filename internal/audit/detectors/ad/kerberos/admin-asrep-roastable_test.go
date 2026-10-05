package kerberos

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// eaDN and eaSID are a stand-in "Enterprise Admins" group (RID -519) used
// across several tests below: DN as it would appear in a user's memberOf,
// and a domain-local SID ending in the corresponding suffix from
// types.PrivilegedSIDSuffixes.
const (
	eaDN  = "CN=Enterprise Admins,CN=Users,DC=example,DC=com"
	eaSID = "S-1-5-21-1111111111-2222222222-3333333333-519"
)

// objectBySIDWithGroupAsrep builds the minimal DetectorData.ObjectBySID index
// this detector reads: one entry mapping a group SID to its DN and
// EntityType, exactly what buildSIDIndex(buildObjectIndex(data)) produces
// from a real collection for a single group.
func objectBySIDWithGroupAsrep(sid, dn string) map[string]*audit.ObjectMeta {
	return map[string]*audit.ObjectMeta{
		sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
	}
}

// TestAdminAsrepRoastable_DisabledAccountExcluded pins the fix: a disabled
// privileged account carrying DONT_REQUIRE_PREAUTH (0x400000) cannot
// authenticate today, so it must not inflate the Critical population - it is
// reported separately by AdminAsrepRoastableOnDisabledAccountDetector
// instead.
func TestAdminAsrepRoastable_DisabledAccountExcluded(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		ObjectBySID:    objectBySIDWithGroupAsrep(eaSID, eaDN),
		Users: []types.User{
			{
				SAMAccountName:     "active-ea",
				UserAccountControl: types.UACDontRequirePreauth,
				Disabled:           false,
				MemberOf:           []string{eaDN},
			},
			{
				SAMAccountName:     "stale-ea",
				UserAccountControl: types.UACDontRequirePreauth,
				Disabled:           true,
				MemberOf:           []string{eaDN},
			},
		},
	}

	findings := NewAdminAsrepRoastableDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled account must be excluded)", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Fatalf("Severity = %s, want critical", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "active-ea" {
		t.Fatalf("AffectedEntities = %+v, want only active-ea", findings[0].AffectedEntities)
	}
}

// TestAdminAsrepRoastable_NotPrivilegedNotFlagged guards the negative case:
// DONT_REQUIRE_PREAUTH alone, without membership in a group whose SID
// carries one of the types.PrivilegedSIDSuffixes RID suffixes, must not be
// flagged by this detector.
func TestAdminAsrepRoastable_NotPrivilegedNotFlagged(t *testing.T) {
	ordinaryDN := "CN=GS-Employees,OU=Groups,DC=example,DC=com"
	data := &audit.DetectorData{
		ObjectBySID: objectBySIDWithGroupAsrep("S-1-5-21-1111111111-2222222222-3333333333-9001", ordinaryDN),
		Users: []types.User{
			{
				SAMAccountName:     "ordinary",
				UserAccountControl: types.UACDontRequirePreauth,
				Disabled:           false,
				MemberOf:           []string{ordinaryDN},
			},
		},
	}

	findings := NewAdminAsrepRoastableDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestAdminAsrepRoastable_NoPreauthBitNotFlagged guards the negative case:
// membership in a privileged group alone, without DONT_REQUIRE_PREAUTH, must
// not be flagged.
func TestAdminAsrepRoastable_NoPreauthBitNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		ObjectBySID: objectBySIDWithGroupAsrep(eaSID, eaDN),
		Users: []types.User{
			{
				SAMAccountName:     "no-preauth-bit",
				UserAccountControl: 0x0200, // NORMAL_ACCOUNT only
				Disabled:           false,
				MemberOf:           []string{eaDN},
			},
		},
	}

	findings := NewAdminAsrepRoastableDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestAdminAsrepRoastable_WidenedCoverageBySuffix pins the coverage gained by
// the SID migration: Key Admins (RID -526) is one of the four groups
// types.PrivilegedSIDSuffixes adds beyond the old seven hardcoded English
// names ("Domain Admins", "Enterprise Admins", "Schema Admins",
// "Administrators", "Account Operators", "Backup Operators", "Server
// Operators"), so a member of Key Admins with the preauth bit was invisible
// to this detector before the migration.
func TestAdminAsrepRoastable_WidenedCoverageBySuffix(t *testing.T) {
	kaDN := "CN=Key Admins,CN=Users,DC=example,DC=com"
	kaSID := "S-1-5-21-1111111111-2222222222-3333333333-526"
	data := &audit.DetectorData{
		IncludeDetails: true,
		ObjectBySID:    objectBySIDWithGroupAsrep(kaSID, kaDN),
		Users: []types.User{
			{
				SAMAccountName:     "ka-member",
				UserAccountControl: types.UACDontRequirePreauth,
				Disabled:           false,
				MemberOf:           []string{kaDN},
			},
		},
	}

	findings := NewAdminAsrepRoastableDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (Key Admins is now covered by RID suffix -526, was never one of the old seven names)", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "ka-member" {
		t.Fatalf("AffectedEntities = %+v, want only ka-member", findings[0].AffectedEntities)
	}
}

// TestAdminAsrepRoastable_LocalizedGroupNameStillMatches is the other half
// of the SID migration: identification no longer depends on an English CN.
// A domain renamed "Enterprise Admins" to its localized display name still
// carries RID -519 on its SID; matching by suffix must catch it where the
// old strings.Contains(dn, "CN=Enterprise Admins") match could not.
func TestAdminAsrepRoastable_LocalizedGroupNameStillMatches(t *testing.T) {
	localizedDN := "CN=Administrateurs de l'entreprise,CN=Users,DC=example,DC=com"
	data := &audit.DetectorData{
		IncludeDetails: true,
		ObjectBySID:    objectBySIDWithGroupAsrep(eaSID, localizedDN),
		Users: []types.User{
			{
				SAMAccountName:     "localized-ea",
				UserAccountControl: types.UACDontRequirePreauth,
				Disabled:           false,
				MemberOf:           []string{localizedDN},
			},
		},
	}

	findings := NewAdminAsrepRoastableDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (localized group name must not defeat the SID-based match)", findings[0].Count)
	}
}

// TestAdminAsrepRoastable_GroupSIDAbsentFromIndexNotFlagged documents the
// known limitation: a group that is genuinely privileged (its real-world SID
// carries a suffix from types.PrivilegedSIDSuffixes) but whose SID never
// made it into DetectorData.ObjectBySID - not collected into data.Groups, or
// collected with an empty ObjectSID - cannot be identified as privileged by
// this detector. This is a property of the shared index
// (engine.collectData / buildSIDIndex), not a defect in this file; the
// detector fails closed (misses the member) rather than open.
func TestAdminAsrepRoastable_GroupSIDAbsentFromIndexNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		ObjectBySID: map[string]*audit.ObjectMeta{}, // empty: SID never indexed
		Users: []types.User{
			{
				SAMAccountName:     "unindexed-ea",
				UserAccountControl: types.UACDontRequirePreauth,
				Disabled:           false,
				MemberOf:           []string{eaDN},
			},
		},
	}

	findings := NewAdminAsrepRoastableDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (group SID absent from ObjectBySID must not be treated as privileged)", findings[0].Count)
	}
}

// TestAdminAsrepRoastable_PartitionIsExhaustiveWithDisabledHalf proves the
// acceptance criterion that both halves of the split share exactly the same
// "privileged" definition: for a fixed set of privileged accounts with the
// DONT_REQUIRE_PREAUTH bit, every account lands in exactly one of the two
// detectors, split only on Disabled, and the two AffectedEntities sets are
// disjoint.
func TestAdminAsrepRoastable_PartitionIsExhaustiveWithDisabledHalf(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		ObjectBySID:    objectBySIDWithGroupAsrep(eaSID, eaDN),
		Users: []types.User{
			{SAMAccountName: "enabled-1", UserAccountControl: types.UACDontRequirePreauth, Disabled: false, MemberOf: []string{eaDN}},
			{SAMAccountName: "enabled-2", UserAccountControl: types.UACDontRequirePreauth, Disabled: false, MemberOf: []string{eaDN}},
			{SAMAccountName: "disabled-1", UserAccountControl: types.UACDontRequirePreauth, Disabled: true, MemberOf: []string{eaDN}},
		},
	}

	critical := NewAdminAsrepRoastableDetector().Detect(context.Background(), data)
	low := NewAdminAsrepRoastableOnDisabledAccountDetector().Detect(context.Background(), data)

	if critical[0].Count != 2 {
		t.Fatalf("critical Count = %d, want 2", critical[0].Count)
	}
	if low[0].Count != 1 {
		t.Fatalf("low Count = %d, want 1", low[0].Count)
	}
	if critical[0].Count+low[0].Count != len(data.Users) {
		t.Fatalf("partition not exhaustive: critical=%d + low=%d != total=%d", critical[0].Count, low[0].Count, len(data.Users))
	}

	seen := map[string]bool{}
	for _, e := range critical[0].AffectedEntities {
		seen[e.SAMAccountName] = true
	}
	for _, e := range low[0].AffectedEntities {
		if seen[e.SAMAccountName] {
			t.Fatalf("%s appears in both the Critical and the disabled-account finding: partition is not disjoint", e.SAMAccountName)
		}
	}
}
