package adcs

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	esc4DomainDN  = "DC=example,DC=com"
	esc4DomainSID = "S-1-5-21-1234567890-1111111111-2222222222"
	esc4Attacker  = esc4DomainSID + "-93801"
	esc4ConfigDN  = "CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com"
)

// TestESC4_EntityOrderIsDeterministic: affectedTemplates
// is a map keyed by template DN, so ranging it directly to build entities
// would give a randomized order per process. With several vulnerable
// templates, an unsorted range would very rarely land in DN order by chance
// across repeated calls - asserting the exact expected order pins the sort.
func TestESC4_EntityOrderIsDeterministic(t *testing.T) {
	names := []string{"Zeta", "Alpha", "Mike", "Bravo"}
	var templates []types.CertTemplate
	var aces []types.ACLEntry
	for _, n := range names {
		dn := "CN=" + n + "," + esc4ConfigDN
		templates = append(templates, types.CertTemplate{DN: dn, Name: n})
		aces = append(aces, types.ACLEntry{
			ObjectDN: dn, Trustee: esc4Attacker, AccessMask: GenericAll, AceType: "ACCESS_ALLOWED",
		})
	}

	want := []string{"CN=Alpha," + esc4ConfigDN, "CN=Bravo," + esc4ConfigDN, "CN=Mike," + esc4ConfigDN, "CN=Zeta," + esc4ConfigDN}

	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: esc4DomainDN, DomainSID: esc4DomainSID},
		CertTemplates:  templates,
		ACLEntries:     aces,
	}

	for i := 0; i < 5; i++ {
		findings := NewESC4Detector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("run %d: expected exactly 1 finding, got %d", i, len(findings))
		}
		ents := findings[0].AffectedEntities
		if len(ents) != len(want) {
			t.Fatalf("run %d: expected %d entities, got %d", i, len(want), len(ents))
		}
		for j, ent := range ents {
			if ent.DN != want[j] {
				t.Fatalf("run %d: entity order not deterministic - position %d = %q, want %q", i, j, ent.DN, want[j])
			}
		}
	}
}

// TestESC4_ScopedWritePropertyNotFlagged_UnscopedIs covers the ecart: an
// ACCESS_ALLOWED_OBJECT WriteProperty ACE with an ObjectType GUID grants write
// access to a single attribute only, not to the whole template. Per
// SpecterOps, Certify wiki, ESC4 ("Vulnerable Certificate Template Access
// Control"), the dangerous "Write Property" case is described as "generic
// write on the object [that] can edit any property" - i.e. only an ACE with
// no ObjectType restriction (empty string here) is equivalent to that. Before
// the fix, isDangerousAccessMask ignored ObjectType entirely, so a template
// whose only non-admin grant was a single scoped attribute write was
// incorrectly reported as vulnerable - exactly the "default ACL noise" this
// ecart flagged.
func TestESC4_ScopedWritePropertyNotFlagged_UnscopedIs(t *testing.T) {
	scopedDN := "CN=Scoped," + esc4ConfigDN
	unscopedDN := "CN=Unscoped," + esc4ConfigDN

	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: esc4DomainDN, DomainSID: esc4DomainSID},
		CertTemplates: []types.CertTemplate{
			{DN: scopedDN, Name: "Scoped"},
			{DN: unscopedDN, Name: "Unscoped"},
		},
		ACLEntries: []types.ACLEntry{
			// WriteProperty scoped to a single, unrelated attribute - must NOT count.
			{ObjectDN: scopedDN, Trustee: esc4Attacker, AccessMask: WriteProperty, AceType: "ACCESS_ALLOWED", ObjectType: "bf967a86-0de6-11d0-a285-00aa003049e2"},
			// WriteProperty with no ObjectType restriction - grants write to every property, must count.
			{ObjectDN: unscopedDN, Trustee: esc4Attacker, AccessMask: WriteProperty, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewESC4Detector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("count = %d, want 1 (only the unscoped WriteProperty template should be flagged)", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].DN != unscopedDN {
		t.Fatalf("affected entities = %+v, want only %q", findings[0].AffectedEntities, unscopedDN)
	}
}

// TestESC4_GenericWriteIsDangerous covers the ecart: GenericWrite was declared
// as a constant and named in this detector's own remediation text
// ("Remove GenericAll, GenericWrite, WriteDACL, ...") but isDangerousAccessMask
// never actually tested the mask against it - a template whose only non-admin
// ACE granted GenericWrite (and nothing else) was silently never reported, a
// real under-reporting bug independent of any external source.
func TestESC4_GenericWriteIsDangerous(t *testing.T) {
	dn := "CN=GW," + esc4ConfigDN
	data := &audit.DetectorData{
		DomainInfo:    &types.DomainInfo{DomainDN: esc4DomainDN, DomainSID: esc4DomainSID},
		CertTemplates: []types.CertTemplate{{DN: dn, Name: "GW"}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: dn, Trustee: esc4Attacker, AccessMask: GenericWrite, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewESC4Detector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("a GenericWrite-only ACE on a non-admin principal should be flagged as dangerous; got findings=%+v", findings)
	}
}

// TestESC4_ServerOperatorsExcluded covers the ecart: the previous admin
// exclusion list (isAdminSID) only covered Domain/Enterprise/Schema Admins,
// built-in Administrators, SYSTEM and Account Operators. Server Operators is
// a well-known BUILTIN privileged group; a default/expected grant to it on a
// certificate template was incorrectly reported as an ESC4 finding. The
// detector now reuses audit.IsPrivilegedSID, the same canonical exclusion
// list every other ACL detector in this codebase relies on, which also
// covers Server/Print/Backup Operators and Key Admins.
func TestESC4_ServerOperatorsExcluded(t *testing.T) {
	dn := "CN=SO," + esc4ConfigDN
	const serverOperators = "S-1-5-32-549" // BUILTIN\Server Operators

	data := &audit.DetectorData{
		DomainInfo:    &types.DomainInfo{DomainDN: esc4DomainDN, DomainSID: esc4DomainSID},
		CertTemplates: []types.CertTemplate{{DN: dn, Name: "SO"}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: dn, Trustee: serverOperators, AccessMask: GenericAll, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewESC4Detector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("Server Operators holding GenericAll should be excluded as a default privileged grant; got findings=%+v", findings)
	}
}
