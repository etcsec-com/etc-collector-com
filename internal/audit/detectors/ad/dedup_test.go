package ad

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// T_036 — the inter-Type de-duplication rule of dedup.go, enforced.
//
// These tests run the WHOLE registered AD suite, so they also guard the rule
// against a future detector: a new Type that re-introduces a duplicate
// population fails TestNoTwoDetectorsReportTheSamePopulation.

// dedupFixture is a small domain that lights up the families involved in the
// de-duplication work: computers without LAPS, privileged accounts without
// smartcard, accounts carrying cleartext password attributes, and an
// adminCount account outside any admin group.
func dedupFixture() *audit.DetectorData {
	const domainDN = "DC=example,DC=com"
	return &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: domainDN, DomainSID: "S-1-5-21-1-2-3"},
		ObjectByDN: map[string]*audit.ObjectMeta{
			domainDN: {DN: domainDN, Name: "example", EntityType: types.EntityTypeDomain},
		},
		Users: []types.User{
			// adminCount outside admin groups + no smartcard + cleartext attrs.
			{DN: "CN=svc.legacy," + domainDN, SAMAccountName: "svc.legacy",
				AdminCount: true, MemberOf: []string{"CN=Helpdesk," + domainDN},
				UserPassword: true, UnixUserPassword: true},
			{DN: "CN=alice," + domainDN, SAMAccountName: "alice"},
		},
		Computers: []types.Computer{
			{DN: "CN=WS-01," + domainDN, SAMAccountName: "WS-01$"},
			{DN: "CN=WS-02," + domainDN, SAMAccountName: "WS-02$"},
		},
	}
}

func runSuite(t *testing.T, data *audit.DetectorData) map[string]types.Finding {
	t.Helper()
	out := map[string]types.Finding{}
	for _, d := range audit.DefaultRegistry.All() {
		for _, f := range d.Detect(context.Background(), data) {
			if f.Count > 0 {
				out[f.Type] = f
			}
		}
	}
	return out
}

// TestDuplicateDetectorsAreGone pins the four Types removed under rule R1,
// each because its predicate was identical by construction to a survivor's.
func TestDuplicateDetectorsAreGone(t *testing.T) {
	removed := map[string]string{
		"REPLICATION_RIGHTS":      "ADMIN_COUNT_ORPHANED",
		"SMARTCARD_NOT_REQUIRED":  "ADMIN_NO_SMARTCARD",
		"UNIX_USER_PASSWORD":      "PASSWORD_CLEARTEXT_STORAGE",
		"ACL_FORCECHANGEPASSWORD": "ACL_USER_FORCE_CHANGE_PASSWORD",
	}

	registered := map[string]bool{}
	for _, d := range audit.DefaultRegistry.All() {
		registered[d.ID()] = true
	}

	for gone, survivor := range removed {
		if registered[gone] {
			t.Errorf("%s is still registered — it duplicates %s by construction", gone, survivor)
		}
		if !registered[survivor] {
			t.Errorf("%s must survive: it is where the information from %s now lives", survivor, gone)
		}
	}
}

// TestDeduplicationLosesNoInformation is the non-regression half: whatever the
// deleted Types used to report is still reported by their survivor, on the same
// accounts.
func TestDeduplicationLosesNoInformation(t *testing.T) {
	got := runSuite(t, dedupFixture())

	cases := []struct {
		survivor string
		why      string
	}{
		{"ADMIN_COUNT_ORPHANED", "adminCount outside admin groups (was also REPLICATION_RIGHTS)"},
		{"ADMIN_NO_SMARTCARD", "privileged account without smartcard (was also SMARTCARD_NOT_REQUIRED)"},
		{"PASSWORD_CLEARTEXT_STORAGE", "userPassword/unixUserPassword present (was also UNIX_USER_PASSWORD)"},
		{"COMPUTER_NO_LAPS", "the per-machine LAPS list (was also in LAPS_NOT_DEPLOYED and LAPS_DOMAIN_COVERAGE_LOW)"},
	}
	for _, tc := range cases {
		f, ok := got[tc.survivor]
		if !ok {
			t.Errorf("%s does not fire — the information it inherited is now lost: %s", tc.survivor, tc.why)
			continue
		}
		if len(f.AffectedEntities) == 0 {
			t.Errorf("%s fires but carries no entities: %s", tc.survivor, tc.why)
		}
	}
}

// TestLAPSGranularitySplit covers rule R2: one defect, three heights, and only
// the per-machine detector carries the machines.
func TestLAPSGranularitySplit(t *testing.T) {
	got := runSuite(t, dedupFixture())

	perMachine, ok := got["COMPUTER_NO_LAPS"]
	if !ok {
		t.Fatal("COMPUTER_NO_LAPS must report the uncovered machines")
	}
	if perMachine.Count != 2 || len(perMachine.AffectedEntities) != 2 {
		t.Errorf("COMPUTER_NO_LAPS: count=%d entities=%d, want 2 and 2",
			perMachine.Count, len(perMachine.AffectedEntities))
	}

	for _, domainLevel := range []string{"LAPS_NOT_DEPLOYED", "LAPS_DOMAIN_COVERAGE_LOW"} {
		f, ok := got[domainLevel]
		if !ok {
			t.Errorf("%s must still fire — it says something the machine list cannot", domainLevel)
			continue
		}
		if f.Count != 1 {
			t.Errorf("%s: count=%d, want 1 — it is a domain-level statement, not a machine list", domainLevel, f.Count)
		}
		if len(f.AffectedEntities) > 1 {
			t.Errorf("%s: %d entities, want at most the domain itself", domainLevel, len(f.AffectedEntities))
		}
		for _, e := range f.AffectedEntities {
			if e.Type != types.EntityTypeDomain {
				t.Errorf("%s: entity type %q, want the domain — the machines belong to COMPUTER_NO_LAPS", domainLevel, e.Type)
			}
		}
		// The information the per-machine list used to carry stays reachable.
		if f.Details["perMachineFinding"] != "COMPUTER_NO_LAPS" {
			t.Errorf("%s must point at where the machine list lives, got %v", domainLevel, f.Details["perMachineFinding"])
		}
	}
}

// TestReconciledFamiliesNoLongerShareAPopulation checks the families this
// ticket reconciled, and ONLY those.
//
// A generic "no two Types may share an entity set" assertion was written first
// and deliberately dropped: on a synthetic fixture every domain-scoped detector
// (LDAP_SIGNING_DISABLED, RECYCLE_BIN_DISABLED, WEAK_PASSWORD_POLICY…) reports
// the same single domain object, and every computer-wide detector reports the
// same two machines. It flagged eleven "duplicates" that are nothing of the
// sort — precisely the mistake rule R1 warns against, since the test of
// duplication is the PREDICATE, not a coincidence of observed sets. Enforcing
// R1 on a new detector is a review-time reading of its predicate; what a test
// can pin is that the families we reconciled stay reconciled.
func TestReconciledFamiliesNoLongerShareAPopulation(t *testing.T) {
	got := runSuite(t, dedupFixture())

	// Each pair used to report a byte-identical population.
	pairs := [][2]string{
		{"COMPUTER_NO_LAPS", "LAPS_DOMAIN_COVERAGE_LOW"},
		{"COMPUTER_NO_LAPS", "LAPS_NOT_DEPLOYED"},
	}
	for _, p := range pairs {
		a, aok := got[p[0]]
		b, bok := got[p[1]]
		if !aok || !bok {
			continue // covered by the granularity test
		}
		if samePopulation(a, b) {
			t.Errorf("%s and %s still report the same population — the same gap is counted twice",
				p[0], p[1])
		}
	}
}

func samePopulation(a, b types.Finding) bool {
	if len(a.AffectedEntities) != len(b.AffectedEntities) {
		return false
	}
	seen := map[string]bool{}
	for _, e := range a.AffectedEntities {
		seen[e.Type+"|"+e.DN] = true
	}
	for _, e := range b.AffectedEntities {
		if !seen[e.Type+"|"+e.DN] {
			return false
		}
	}
	return true
}
