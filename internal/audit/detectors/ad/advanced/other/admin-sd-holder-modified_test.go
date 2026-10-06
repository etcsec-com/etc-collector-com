package other

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// This detector never read AccessMask at all before this fix (motif(b),
// same signature as the bugs the dangerous_acl_test.go suite covers): ANY
// ACCESS_ALLOWED ACE on AdminSDHolder from a non-default SID was flagged HIGH
// severity regardless of what right it actually granted. Live proof against
// DC01 confirms the fix behaves correctly against real
// AD data; this table-driven test pins the exact boundary deterministically -
// AccessMaskToRight (aclentry.go) never renders a plain read-only right as a
// named entity, so a live-only demonstration cannot show the negative case by
// entity name alone.

const (
	asdhDomainDN = "DC=example,DC=com"
	asdhDomain   = "S-1-5-21-1234567890-1111111111-2222222222"
	asdhObjectDN = "CN=AdminSDHolder,CN=System," + asdhDomainDN

	// An ordinary domain principal, not one of isDefaultAdminSDHolderSID's SIDs.
	asdhOrdinarySID = asdhDomain + "-93801"

	maskReadProperty = 0x00000010 // ADS_RIGHT_DS_READ_PROP - not in dangerousMask
	maskWriteDACL    = 0x00040000
)

func asdhData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		DomainInfo:     &types.DomainInfo{DomainSID: asdhDomain},
	}
}

func TestAdminSDHolderModified_RequiresDangerousRight(t *testing.T) {
	t.Run("read-only grant from a non-default SID does NOT fire", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: asdhOrdinarySID, AccessMask: maskReadProperty, AceType: "ACCESS_ALLOWED"},
		))
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 0 {
			t.Fatalf("a read-only ACE must not be flagged as a modification, got count=%d", findings[0].Count)
		}
	})

	t.Run("WriteDACL grant from a non-default SID DOES fire", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: asdhOrdinarySID, AccessMask: maskWriteDACL, AceType: "ACCESS_ALLOWED"},
		))
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 1 {
			t.Fatalf("a WriteDACL grant to a non-default principal must fire, got count=%d", findings[0].Count)
		}
		if len(findings[0].AffectedEntities) != 1 {
			t.Fatalf("finding must be actionable, got %d entities", len(findings[0].AffectedEntities))
		}
	})

	t.Run("deny ACE with a dangerous mask still does not fire", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: asdhOrdinarySID, AccessMask: maskWriteDACL, AceType: "ACCESS_DENIED"},
		))
		if findings[0].Count != 0 {
			t.Fatalf("a DENY ACE must never be counted as a grant, got count=%d", findings[0].Count)
		}
	})
}

// A pristine, never-touched AdminSDHolder still carries two default
// attribute-scoped WriteProperty ACEs documented by Microsoft ("Appendix K:
// Default Settings in the Master Security Descriptor of the AdminSDHolder
// Object"): Cert Publishers (RP;WP on userCert) and Terminal Server License
// Servers (RP;WP on terminalServer). Before isDefaultAdminSDHolderSID knew
// about them, both were indistinguishable from an attacker-granted
// WriteProperty right and a virgin object was reported "Modified".
func TestAdminSDHolderModified_DefaultAttributeScopedACEsDoNotFire(t *testing.T) {
	t.Run("Cert Publishers default WriteProperty-on-userCert ACE does NOT fire", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: asdhDomain + "-517", AccessMask: types.MaskWriteProperty, AceType: "ACCESS_ALLOWED"},
		))
		if findings[0].Count != 0 {
			t.Fatalf("Cert Publishers' default userCert ACE must not be reported as a modification, got count=%d", findings[0].Count)
		}
	})

	t.Run("Terminal Server License Servers default WriteProperty-on-terminalServer ACE does NOT fire", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: "S-1-5-32-561", AccessMask: types.MaskWriteProperty, AceType: "ACCESS_ALLOWED"},
		))
		if findings[0].Count != 0 {
			t.Fatalf("Terminal Server License Servers' default terminalServer ACE must not be reported as a modification, got count=%d", findings[0].Count)
		}
	})
}
