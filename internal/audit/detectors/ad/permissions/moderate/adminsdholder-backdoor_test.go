package moderate

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const adminSDHolderDN = "CN=AdminSDHolder,CN=System,DC=contoso,DC=com"

// TestAdminSDHolderBackdoor_FiltersBaselineACEs covers a bug where the
// detector counted every ACE on AdminSDHolder as a "backdoor", including the
// baseline SDProp grants (Domain Admins, deny-ACEs) that exist on every AD
// domain by construction. Sibling detectors (writeowner.go, genericall.go,
// and others) already filter grant-only + non-admin trustees - this detector
// never received those two filters.
func TestAdminSDHolderBackdoor_FiltersBaselineACEs(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			// Baseline: Domain Admins grant - expected, not a finding.
			{ObjectDN: adminSDHolderDN, Trustee: "S-1-5-21-1-2-3-512", AccessMask: 0x000F01FF, AceType: "ACCESS_ALLOWED"},
			// Baseline: a DENY ace grants nothing.
			{ObjectDN: adminSDHolderDN, Trustee: "S-1-5-21-1-2-3-9999", AccessMask: 0x000F01FF, AceType: "ACCESS_DENIED"},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (baseline SDProp ACEs must not count as a backdoor), got %d", findings[0].Count)
	}
}

// TestAdminSDHolderBackdoor_FiresOnNonAdminGrant guards against
// over-filtering: a real grant to a non-admin trustee must still fire.
func TestAdminSDHolderBackdoor_FiresOnNonAdminGrant(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: adminSDHolderDN, Trustee: "S-1-5-21-1-2-3-9999", AccessMask: 0x000F01FF, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 for a real non-admin grant, got %d", findings[0].Count)
	}
}
