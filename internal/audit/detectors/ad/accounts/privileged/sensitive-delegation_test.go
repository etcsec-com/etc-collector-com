package privileged

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// reSensitiveDelegationActiveTextGuard guards THIS ACTIVE (Critical)
// detector's text against reintroducing disabled accounts as covered: the
// bare word "disabled", and the specific formulas the KDC measurement in
// docs/security-validation/results/unconstrained-delegation-disabled-v2/VERDICT.md
// refuted (a disabled account is neither a valid delegation origin nor
// target, and the KDC does check the account's enabled state on both the TGT
// and the service-ticket path). Deliberately NOT shared with
// sensitive-delegation-on-disabled-account_test.go's
// reSensitiveDelegationRefutedClaim: that detector's own Description
// legitimately talks about disabled accounts, so a bare "disabled" match
// would misfire there.
var reSensitiveDelegationActiveTextGuard = regexp.MustCompile(`(?i)\bdisabled\b|\bnever revalidates\b|\bnever checks\b|\bdoes not revalidate\b|\bregardless of account status\b|\bremains a valid delegation target\b|\bwhether enabled or disabled\b`)

// daDN and daSID are a stand-in "Domain Admins" group (RID -512) used across
// several tests below: DN as it would appear in a user's memberOf, and a
// domain-local SID ending in the corresponding suffix from
// types.PrivilegedSIDSuffixes.
const (
	daDN  = "CN=Domain Admins,CN=Users,DC=example,DC=com"
	daSID = "S-1-5-21-1111111111-2222222222-3333333333-512"
)

// objectBySIDWithGroup builds the minimal DetectorData.ObjectBySID index this
// detector reads: one entry mapping a group SID to its DN and EntityType,
// exactly what buildSIDIndex(buildObjectIndex(data)) produces from a real
// collection for a single group.
func objectBySIDWithGroup(sid, dn string) map[string]*audit.ObjectMeta {
	return map[string]*audit.ObjectMeta{
		sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
	}
}

// TestSensitiveDelegation_DisabledAccountExcluded pins the fix: a disabled
// privileged account carrying TRUSTED_FOR_DELEGATION (0x80000) cannot
// authenticate today, so it must not inflate the Critical population - it is
// reported separately by SensitiveDelegationOnDisabledAccountDetector
// instead.
func TestSensitiveDelegation_DisabledAccountExcluded(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		ObjectBySID:    objectBySIDWithGroup(daSID, daDN),
		Users: []types.User{
			{
				SAMAccountName:     "active-da",
				UserAccountControl: types.UACTrustedForDelegation,
				Disabled:           false,
				MemberOf:           []string{daDN},
			},
			{
				SAMAccountName:     "stale-da",
				UserAccountControl: types.UACTrustedForDelegation,
				Disabled:           true,
				MemberOf:           []string{daDN},
			},
		},
	}

	findings := NewSensitiveDelegationDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled account must be excluded)", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Fatalf("Severity = %s, want critical", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "active-da" {
		t.Fatalf("AffectedEntities = %+v, want only active-da", findings[0].AffectedEntities)
	}
}

// TestSensitiveDelegation_NotPrivilegedNotFlagged guards the negative case:
// unconstrained delegation alone, without membership in a group whose SID
// carries one of the types.PrivilegedSIDSuffixes RID suffixes, must not be
// flagged by this detector.
func TestSensitiveDelegation_NotPrivilegedNotFlagged(t *testing.T) {
	ordinaryDN := "CN=GS-Employees,OU=Groups,DC=example,DC=com"
	data := &audit.DetectorData{
		// The index carries the ordinary group too (SID with no privileged
		// suffix), so the negative result comes from the suffix test, not
		// from an empty index.
		ObjectBySID: objectBySIDWithGroup("S-1-5-21-1111111111-2222222222-3333333333-9001", ordinaryDN),
		Users: []types.User{
			{
				SAMAccountName:     "ordinary",
				UserAccountControl: types.UACTrustedForDelegation,
				Disabled:           false,
				MemberOf:           []string{ordinaryDN},
			},
		},
	}

	findings := NewSensitiveDelegationDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestSensitiveDelegation_NoDelegationNotFlagged guards the negative case:
// membership in a privileged group alone, without the delegation bit, must
// not be flagged.
func TestSensitiveDelegation_NoDelegationNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		ObjectBySID: objectBySIDWithGroup(daSID, daDN),
		Users: []types.User{
			{
				SAMAccountName:     "no-delegation",
				UserAccountControl: 0x0200, // NORMAL_ACCOUNT only
				Disabled:           false,
				MemberOf:           []string{daDN},
			},
		},
	}

	findings := NewSensitiveDelegationDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestSensitiveDelegation_WidenedCoverageBySuffix is a regression test:
// Account Operators (RID -548) was never one of the four hardcoded
// English names ("Domain Admins", "Enterprise Admins", "Schema Admins",
// "Administrators") the old strings.Contains(dn, "CN="+name) match covered,
// so a member of Account Operators with the delegation bit was invisible to
// this detector before the migration to SID-based matching.
// types.PrivilegedSIDSuffixes carries "-548": "Account Operators", so the
// SID-based match must now catch it.
func TestSensitiveDelegation_WidenedCoverageBySuffix(t *testing.T) {
	aoDN := "CN=Account Operators,CN=Builtin,DC=example,DC=com"
	aoSID := "S-1-5-21-1111111111-2222222222-3333333333-548"
	data := &audit.DetectorData{
		IncludeDetails: true,
		ObjectBySID:    objectBySIDWithGroup(aoSID, aoDN),
		Users: []types.User{
			{
				SAMAccountName:     "ao-member",
				UserAccountControl: types.UACTrustedForDelegation,
				Disabled:           false,
				MemberOf:           []string{aoDN},
			},
		},
	}

	findings := NewSensitiveDelegationDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (Account Operators is now covered by RID suffix -548)", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "ao-member" {
		t.Fatalf("AffectedEntities = %+v, want only ao-member", findings[0].AffectedEntities)
	}
}

// TestSensitiveDelegation_LocalizedGroupNameStillMatches proves the other
// half of the migration's objective: identification no longer depends on an
// English CN. A domain renamed "Domain Admins" to its localized display name still
// carries RID -512 on its SID; matching by suffix must catch it where the
// old strings.Contains(dn, "CN=Domain Admins") match could not.
func TestSensitiveDelegation_LocalizedGroupNameStillMatches(t *testing.T) {
	localizedDN := "CN=Admins du domaine,CN=Users,DC=example,DC=com"
	data := &audit.DetectorData{
		IncludeDetails: true,
		ObjectBySID:    objectBySIDWithGroup(daSID, localizedDN),
		Users: []types.User{
			{
				SAMAccountName:     "localized-da",
				UserAccountControl: types.UACTrustedForDelegation,
				Disabled:           false,
				MemberOf:           []string{localizedDN},
			},
		},
	}

	findings := NewSensitiveDelegationDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (localized group name must not defeat the SID-based match)", findings[0].Count)
	}
}

// TestSensitiveDelegation_GroupSIDAbsentFromIndexNotFlagged documents a
// known limitation: a group that is genuinely privileged
// (its real-world SID carries a suffix from types.PrivilegedSIDSuffixes) but
// whose SID never made it into DetectorData.ObjectBySID - not collected into
// data.Groups, or collected with an empty ObjectSID - cannot be identified
// as privileged by this detector. This is a property of the shared index
// (engine.collectData / buildSIDIndex), not a defect in this file; the
// detector fails closed (misses the member) rather than open.
func TestSensitiveDelegation_GroupSIDAbsentFromIndexNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		ObjectBySID: map[string]*audit.ObjectMeta{}, // empty: SID never indexed
		Users: []types.User{
			{
				SAMAccountName:     "unindexed-da",
				UserAccountControl: types.UACTrustedForDelegation,
				Disabled:           false,
				MemberOf:           []string{daDN},
			},
		},
	}

	findings := NewSensitiveDelegationDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (group SID absent from ObjectBySID must not be treated as privileged)", findings[0].Count)
	}
}

// TestSensitiveDelegation_PartitionIsExhaustiveWithDisabledHalf proves the
// acceptance criterion that both halves of the split share exactly the same
// "privileged" definition: for a fixed set of privileged accounts with the
// delegation bit, every account lands in exactly one of the two detectors,
// split only on Disabled, and the two AffectedEntities sets are disjoint.
func TestSensitiveDelegation_PartitionIsExhaustiveWithDisabledHalf(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		ObjectBySID:    objectBySIDWithGroup(daSID, daDN),
		Users: []types.User{
			{SAMAccountName: "enabled-1", UserAccountControl: types.UACTrustedForDelegation, Disabled: false, MemberOf: []string{daDN}},
			{SAMAccountName: "enabled-2", UserAccountControl: types.UACTrustedForDelegation, Disabled: false, MemberOf: []string{daDN}},
			{SAMAccountName: "disabled-1", UserAccountControl: types.UACTrustedForDelegation, Disabled: true, MemberOf: []string{daDN}},
		},
	}

	critical := NewSensitiveDelegationDetector().Detect(context.Background(), data)
	low := NewSensitiveDelegationOnDisabledAccountDetector().Detect(context.Background(), data)

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

// TestSensitiveDelegation_DescriptionNoDisabledLanguage guards the
// Description string returned by Detect(): this active/Critical detector's
// text must never claim to cover disabled accounts.
func TestSensitiveDelegation_DescriptionNoDisabledLanguage(t *testing.T) {
	data := &audit.DetectorData{
		ObjectBySID: objectBySIDWithGroup(daSID, daDN),
		Users: []types.User{
			{SAMAccountName: "active-da", UserAccountControl: types.UACTrustedForDelegation, Disabled: false, MemberOf: []string{daDN}},
		},
	}
	findings := NewSensitiveDelegationDetector().Detect(context.Background(), data)
	if reSensitiveDelegationActiveTextGuard.MatchString(findings[0].Description) {
		t.Fatalf("Description must not mention disabled accounts or a refuted KDC claim: %q", findings[0].Description)
	}
}

// TestSensitiveDelegation_DocNoDisabledLanguage is the Doc()-only
// counterpart: docs_gen.go is a separate copy, not test-coupled to Detect()'s
// Description by the Go compiler.
func TestSensitiveDelegation_DocNoDisabledLanguage(t *testing.T) {
	doc := NewSensitiveDelegationDetector().Doc()
	if reSensitiveDelegationActiveTextGuard.MatchString(doc.Description) {
		t.Fatalf("Doc().Description must not mention disabled accounts or a refuted KDC claim: %q", doc.Description)
	}
}

// TestSensitiveDelegation_DescriptionStartsWithEnabled guards the positive
// claim: the text must open by naming the population it actually covers.
func TestSensitiveDelegation_DescriptionStartsWithEnabled(t *testing.T) {
	data := &audit.DetectorData{
		ObjectBySID: objectBySIDWithGroup(daSID, daDN),
		Users: []types.User{
			{SAMAccountName: "active-da", UserAccountControl: types.UACTrustedForDelegation, Disabled: false, MemberOf: []string{daDN}},
		},
	}
	findings := NewSensitiveDelegationDetector().Detect(context.Background(), data)
	if !strings.HasPrefix(findings[0].Description, "Enabled") {
		t.Fatalf("Description must start with %q, got %q", "Enabled", findings[0].Description)
	}
}

// TestSensitiveDelegation_DocStartsWithEnabled is the Doc()-only counterpart
// of TestSensitiveDelegation_DescriptionStartsWithEnabled.
func TestSensitiveDelegation_DocStartsWithEnabled(t *testing.T) {
	doc := NewSensitiveDelegationDetector().Doc()
	if !strings.HasPrefix(doc.Description, "Enabled") {
		t.Fatalf("Doc().Description must start with %q, got %q", "Enabled", doc.Description)
	}
}
