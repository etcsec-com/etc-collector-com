package anssi

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// tier0CriterionRegression matches any wording that would (re)claim
// AdminCount or AdminSDHolder as a Tier 0 recognition criterion. A
// verification pass found this Description still making this exact claim
// ("recursive expansion + AdminSDHolder") while
// helpers.Tier0Members/Tier0Groups no longer read AdminCount at all - the
// neighboring KERBEROASTING_RISK guard at the time only matched the glued
// token "admincount" and would have missed both this spelling and a
// "AdminSDHolder"-only regression. `admin.?count` covers the glued and
// single-separator spellings; `adminsdholder` covers the mechanism name
// directly. Word boundaries keep it from firing on unrelated words.
var tier0CriterionRegression = regexp.MustCompile(`(?i)\badmin.?count\b|\badminsdholder\b`)

// wellKnownSIDMention matches the word "sid" on its own, case-insensitive,
// mirroring the guard used by KERBEROASTING_RISK's own text test (same
// package family, same Tier 0 recognition rule).
var wellKnownSIDMention = regexp.MustCompile(`(?i)\bsid\b`)

// TestR40NoPSOTier0Description_DoesNotClaimAdminCountAsTier0Criterion locks
// the Description delivered to the client to the Tier 0 recognition
// Detect() actually applies: AdminCount=1/AdminSDHolder is not a Tier 0
// recognition path in helpers.Tier0Members/Tier0Groups - the text must not
// claim otherwise, and must keep naming the SID-based recognition that
// governs it instead.
func TestR40NoPSOTier0Description_DoesNotClaimAdminCountAsTier0Criterion(t *testing.T) {
	domainDN := "DC=test,DC=local"
	const domainAdminsSID = "S-1-5-21-1112223334-4445556667-7778889990-512"
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: domainDN},
		Groups: []types.Group{
			{DN: "CN=Domain Admins,CN=Users," + domainDN, SAMAccountName: "Domain Admins", ObjectSID: domainAdminsSID},
		},
		// No FGPPs at all - none of the Tier 0 groups is covered by a PSO.
	}

	findings := NewR40NoPSOTier0Detector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}

	desc := findings[0].Description
	if tier0CriterionRegression.MatchString(desc) {
		t.Errorf("Description must not name AdminCount or AdminSDHolder as a Tier 0 criterion - got: %q", desc)
	}
	if !wellKnownSIDMention.MatchString(desc) {
		t.Errorf("Description must name SID-based recognition as the Tier 0 criterion - got: %q", desc)
	}
}

// TestR40NoPSOTier0Doc_DoesNotClaimAdminCountAsTier0Criterion ties the
// catalog Doc().Description - shown to the client independently of any live
// audit, in docs and in the catalog markdown - to the exact same guard as
// the Detect()-time Description above. The verifier's mutation M5 proved
// these two texts can drift apart silently: reverting Doc() (and the
// catalog) to the old "AdminSDHolder" wording while leaving Detect()'s
// Description fixed left every prior test green, because no test read Doc()
// at all.
func TestR40NoPSOTier0Doc_DoesNotClaimAdminCountAsTier0Criterion(t *testing.T) {
	desc := NewR40NoPSOTier0Detector().Doc().Description
	if tier0CriterionRegression.MatchString(desc) {
		t.Errorf("Doc().Description must not name AdminCount or AdminSDHolder as a Tier 0 criterion - got: %q", desc)
	}
	if !wellKnownSIDMention.MatchString(desc) {
		t.Errorf("Doc().Description must name SID-based recognition as the Tier 0 criterion - got: %q", desc)
	}
}

// TestR40NoPSOTier0_EntityOrderIsDeterministic exists because the
// uncovered Tier 0 groups come from helpers.Tier0Groups, a map, so ranging it
// directly to build entities would give a randomized order per process. With
// several Tier 0 groups and no PSO covering any of them, an unsorted range
// would very rarely land in DN order by chance across repeated calls -
// asserting the exact expected order pins the sort.
func TestR40NoPSOTier0_EntityOrderIsDeterministic(t *testing.T) {
	const domainDN = "DC=example,DC=com"
	// SID suffixes match tier0SeedRIDSuffixes (helpers/tier0.go) by RID, not
	// by these groups' names: seed matching is now SID-based, so a fixture
	// without ObjectSID would no longer be recognized as Tier 0 at all.
	// Domain identifier chosen independently of any constant in the helpers
	// package.
	const testDomainSID = "S-1-5-21-5551110000-5552220000-5553330000"
	groups := []types.Group{
		{DN: "CN=Domain Admins,CN=Users," + domainDN, SAMAccountName: "Domain Admins", ObjectSID: testDomainSID + "-512"},
		{DN: "CN=Enterprise Admins,CN=Users," + domainDN, SAMAccountName: "Enterprise Admins", ObjectSID: testDomainSID + "-519"},
		{DN: "CN=Schema Admins,CN=Users," + domainDN, SAMAccountName: "Schema Admins", ObjectSID: testDomainSID + "-518"},
		{DN: "CN=Administrators,CN=Builtin," + domainDN, SAMAccountName: "Administrators", ObjectSID: "S-1-5-32-544"},
	}

	// helpers.Tier0Groups keys its set by LOWERCASE DN, and data.EntityForDN
	// does an exact (case-sensitive) map lookup against data.ObjectByDN - so
	// with no ObjectByDN cache populated (as here), the entities come back
	// unresolved with the lowercase DN. That case-sensitivity gap is
	// pre-existing and not what this test is about; it just means the
	// expected DNs below are lowercase to match real behavior.
	lowerDomainDN := strings.ToLower(domainDN)
	want := []string{
		"cn=administrators,cn=builtin," + lowerDomainDN,
		"cn=domain admins,cn=users," + lowerDomainDN,
		"cn=enterprise admins,cn=users," + lowerDomainDN,
		"cn=schema admins,cn=users," + lowerDomainDN,
	}

	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: domainDN},
		Groups:         groups,
		// No FGPPs at all - none of the Tier 0 groups is covered by a PSO.
	}

	for i := 0; i < 5; i++ {
		findings := NewR40NoPSOTier0Detector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("run %d: expected exactly 1 finding, got %d", i, len(findings))
		}
		ents := findings[0].AffectedEntities
		if len(ents) != len(want) {
			t.Fatalf("run %d: expected %d entities, got %d (%v)", i, len(want), len(ents), ents)
		}
		for j, ent := range ents {
			if ent.DN != want[j] {
				t.Fatalf("run %d: entity order not deterministic - position %d = %q, want %q", i, j, ent.DN, want[j])
			}
		}
	}
}
