package advanced

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// [MS-ADTS] "dSHeuristics" (character table, row 7 "fLDAPBlockAnonOps"):
// "If this character is '2', then the fLDAPBlockAnonOps heuristic is
// FALSE" (anonymous LDAP operations are NOT blocked, i.e. allowed);
// otherwise the heuristic is TRUE (blocked). The spec's own worked example
// for *enabling* anonymous LDAP operations produces the 7-character string
// "0000002" - exactly the value measured on this repo's lab DC.
//
// The detector previously read index 7 (the 8th character, fAllowAnonNSPI
// - a different heuristic) with the comparison direction inverted. On a
// 7-character string such as the lab's, the "len(dsh) > 7" guard is false,
// so the check silently never ran at all - a false "secure" result by
// accident. This test fails against that old code (no issue is raised for
// "0000002") and passes once the fix reads index 6 with the correct '2'
// == allowed direction.
func TestDsHeuristicsLDAPSecurity_SeventhCharAnonOpsAllowed(t *testing.T) {
	d := NewDsHeuristicsLDAPSecurityDetector()

	findings := d.Detect(context.Background(), &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DsHeuristics: "0000002"},
	})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}

	issues, ok := findings[0].Details["issues"].([]string)
	if !ok {
		t.Fatalf("expected Details[\"issues\"] to be a []string, got %#v", findings[0].Details["issues"])
	}

	want := "Position 7 (fLDAPBlockAnonOps) is set to '2' - anonymous LDAP operations are allowed"
	for _, issue := range issues {
		if issue == want {
			return
		}
	}
	t.Fatalf("dsHeuristics=%q (7th char '2' means anonymous LDAP ops are allowed per [MS-ADTS]) did not surface the expected issue; got issues=%v", "0000002", issues)
}

// A dsHeuristics value whose 7th character is NOT '2' blocks anonymous LDAP
// operations per [MS-ADTS] and must not raise the fLDAPBlockAnonOps issue,
// even though it is still short enough to trip the unrelated
// CVE-2021-42291 (position 28/29) checks.
func TestDsHeuristicsLDAPSecurity_SeventhCharBlockedNotFlagged(t *testing.T) {
	d := NewDsHeuristicsLDAPSecurityDetector()

	findings := d.Detect(context.Background(), &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DsHeuristics: "0000000"},
	})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}

	issues, _ := findings[0].Details["issues"].([]string)
	dontWant := "Position 7 (fLDAPBlockAnonOps) is set to '2' - anonymous LDAP operations are allowed"
	for _, issue := range issues {
		if issue == dontWant {
			t.Fatalf("dsHeuristics=%q (7th char '0' blocks anonymous ops per [MS-ADTS]) must not raise the anon-ops issue; got issues=%v", "0000000", issues)
		}
	}
}
