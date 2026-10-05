package helpers

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Fake domain SID prefix used across this file. Literal, chosen independently
// of any constant in tier0.go - a fixture built from strings.HasSuffix(sid,
// "-512") reasoning would trivially always match its own constant; these
// values are typed out by hand instead, the way a real AD domain SID looks.
const testDomainSIDPrefix = "S-1-5-21-1111111111-2222222222-3333333333"

func TestTier0Members_DirectMembership(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Domain Admins", DN: "CN=Domain Admins,DC=test,DC=local",
				ObjectSID: testDomainSIDPrefix + "-512",
				Members:   []string{"CN=alice,DC=test,DC=local", "CN=bob,DC=test,DC=local"}},
		},
	}
	got := Tier0Members(data, nil)
	if !got["cn=alice,dc=test,dc=local"] || !got["cn=bob,dc=test,dc=local"] {
		t.Fatalf("expected alice + bob in Tier 0, got %v", got)
	}
}

func TestTier0Members_RecursiveNesting(t *testing.T) {
	// Domain Admins ⊃ NestedAdmins ⊃ deepUser
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local",
				ObjectSID: testDomainSIDPrefix + "-512",
				Members:   []string{"CN=NestedAdmins,DC=test,DC=local"}},
			{SAMAccountName: "NestedAdmins", DN: "CN=NestedAdmins,DC=test,DC=local",
				Members: []string{"CN=deepUser,DC=test,DC=local"}},
		},
	}
	got := Tier0Members(data, nil)
	if !got["cn=deepuser,dc=test,dc=local"] {
		t.Fatalf("recursive expansion missed deepUser, got %v", got)
	}
}

// TestTier0Members_AdminCountAloneIsNotTier0 replaces the old
// TestTier0Members_AdminCountOne (D4): AdminCount=1 with zero current group
// membership used to be enough to be flagged Tier 0. It no longer is - that
// population is ADMIN_COUNT_ORPHANED's job, not this helper's. This is the
// negative counterpart the ticket's acceptance criterion asks for ("adminCount=1
// seul ne classe plus Tier 0, prouvé par test").
func TestTier0Members_AdminCountAloneIsNotTier0(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=ghost,DC=test,DC=local", SAMAccountName: "ghost", AdminCount: true},
		},
	}
	got := Tier0Members(data, nil)
	if got["cn=ghost,dc=test,dc=local"] {
		t.Fatalf("AdminCount=1 alone (no group membership) must NOT be Tier 0 after D4, got %v", got)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty Tier 0 set, got %v", got)
	}
}

func TestTier0Members_CustomGroupDNs(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Acme-T0", DN: "CN=Acme-T0,OU=AcmeAdmins,DC=test,DC=local",
				Members: []string{"CN=charlie,DC=test,DC=local"}},
		},
	}
	custom := []string{"CN=Acme-T0,OU=AcmeAdmins,DC=test,DC=local"}
	got := Tier0Members(data, custom)
	if !got["cn=charlie,dc=test,dc=local"] {
		t.Fatalf("custom Tier 0 group member missed, got %v", got)
	}
}

func TestTier0Members_CycleDoesNotInfinite(t *testing.T) {
	// Domain Admins ⊃ Loop ⊃ Domain Admins (cycle). Must terminate.
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local",
				ObjectSID: testDomainSIDPrefix + "-512",
				Members:   []string{"CN=Loop,DC=test,DC=local"}},
			{SAMAccountName: "Loop", DN: "CN=Loop,DC=test,DC=local",
				Members: []string{"CN=DA,DC=test,DC=local", "CN=enduser,DC=test,DC=local"}},
		},
	}
	got := Tier0Members(data, nil)
	if !got["cn=enduser,dc=test,dc=local"] {
		t.Fatalf("cycle case should still expand to enduser, got %v", got)
	}
}

func TestTier0Groups_TransitiveNesting(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local",
				ObjectSID: testDomainSIDPrefix + "-512",
				Members:   []string{"CN=Inner,DC=test,DC=local"}},
			{SAMAccountName: "Inner", DN: "CN=Inner,DC=test,DC=local"},
		},
	}
	got := Tier0Groups(data, nil)
	if !got["cn=inner,dc=test,dc=local"] {
		t.Fatalf("Inner group should be Tier 0 by nesting, got %v", got)
	}
}

// TestTier0Groups_MatchesByRIDNotName is the SID-over-name witness: a group
// renamed away from every English default name, but carrying the real
// Domain Admins RID (-512), must still be recognized as Tier 0. This is the
// fix for a failure demonstrated on a live lab forest: renaming a real
// seed group (DnsAdmins) broke name-based recognition while the group's
// real privilege (and real SID) hadn't changed at all.
func TestTier0Groups_MatchesByRIDNotName(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Admins-du-domaine", DN: "CN=Admins-du-domaine,DC=test,DC=local",
				ObjectSID: testDomainSIDPrefix + "-512"},
		},
	}
	got := Tier0Groups(data, nil)
	if !got["cn=admins-du-domaine,dc=test,dc=local"] {
		t.Fatalf("group with real -512 RID must be Tier 0 regardless of its name, got %v", got)
	}
}

// TestTier0Groups_NameAloneWithoutRIDIsNotTier0 is the other half of the
// same witness pair: a brand-new group literally named "Domain Admins" but
// NOT carrying the real RID must NOT be Tier 0. A fresh, unprivileged group
// must not be classified Tier 0 just because its name happens to collide
// with a well-known one.
func TestTier0Groups_NameAloneWithoutRIDIsNotTier0(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Domain Admins", DN: "CN=Fresh,DC=test,DC=local",
				ObjectSID: testDomainSIDPrefix + "-9931"}, // freshly allocated RID, not a well-known one
		},
	}
	got := Tier0Groups(data, nil)
	if got["cn=fresh,dc=test,dc=local"] {
		t.Fatalf("a group merely NAMED Domain Admins, without the real RID, must not be Tier 0, got %v", got)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty Tier 0 group set, got %v", got)
	}
}

// TestTier0Groups_DnsAdminsMatchesByNameOnly documents D2: DnsAdmins has no
// fixed RID, so it stays matched by name. Its SID here is deliberately a
// non-privileged, dynamically-allocated-looking RID, to prove the name path
// (not an accidental RID collision) is what admits it.
func TestTier0Groups_DnsAdminsMatchesByNameOnly(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "DnsAdmins", DN: "CN=DnsAdmins,CN=Users,DC=test,DC=local",
				ObjectSID: testDomainSIDPrefix + "-1101"},
		},
	}
	got := Tier0Groups(data, nil)
	if !got["cn=dnsadmins,cn=users,dc=test,dc=local"] {
		t.Fatalf("DnsAdmins must match by name (D2 - no fixed RID exists), got %v", got)
	}
}

// TestTier0Groups_ProtectedUsersNeverSeed guards D3: Protected Users has a
// real, fixed, Microsoft-documented RID (-525) - unlike DnsAdmins, it COULD
// be matched by RID - but it is deliberately excluded from
// tier0SeedRIDSuffixes because it restricts its members rather than
// privileging them. This test would catch an accidental future re-addition
// of "-525" to that table.
func TestTier0Groups_ProtectedUsersNeverSeed(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Protected Users", DN: "CN=Protected Users,CN=Users,DC=test,DC=local",
				ObjectSID: testDomainSIDPrefix + "-525"},
		},
	}
	got := Tier0Groups(data, nil)
	if got["cn=protected users,cn=users,dc=test,dc=local"] {
		t.Fatalf("Protected Users must never be a Tier 0 seed (D3), got %v", got)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty Tier 0 group set, got %v", got)
	}
}

// TestIsTier0SeedRIDSuffix_NoFalsePositiveOnLongerRID is a direct unit test
// of the suffix-matching pitfall documented on IsBuiltinAdminTrustee
// (wellknown_sids.go) and repeated in this file's doc comment: a SID ending
// in "-1512" must not match the "-512" suffix.
func TestIsTier0SeedRIDSuffix_NoFalsePositiveOnLongerRID(t *testing.T) {
	if isTier0SeedRIDSuffix(testDomainSIDPrefix + "-1512") {
		t.Fatalf("-1512 must not match the -512 suffix")
	}
	if !isTier0SeedRIDSuffix(testDomainSIDPrefix + "-512") {
		t.Fatalf("-512 must match its own suffix")
	}
	// A sub-authority that happens to START WITH "512" (a realistic random
	// 32-bit sub-authority value, e.g. 5127777777) makes "-512" appear as a
	// SUBSTRING in the middle of the SID, without the SID ending in -512 at
	// all. strings.Contains would wrongly match this; strings.HasSuffix
	// (anchored at the true end of the string) must not.
	if isTier0SeedRIDSuffix("S-1-5-21-5127777777-2222222222-3333333333-9999") {
		t.Fatalf("-512 appearing mid-string (not at the end) must not match")
	}
}
