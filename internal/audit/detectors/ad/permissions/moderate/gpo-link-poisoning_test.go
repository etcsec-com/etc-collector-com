package moderate

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// The detector never checked AceType, so a DENY ACE carrying the
// GenericAll/GenericWrite/WriteDACL bits was counted the same as an ALLOW
// grant - the bug signature (a DENY ACE grants nothing). This test
// fails against the old code (the DENY ACE is wrongly counted, Count=1) and
// passes once AceType is checked via audit.IsGrantACE (Count=0).
func TestGPOLinkPoisoning_DenyACEDoesNotCount(t *testing.T) {
	const writeDACL = 0x00040000
	containerDN := "CN=Policies,CN=System,DC=test,DC=local"

	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: containerDN, Trustee: "S-1-5-21-1-2-3-1234", AccessMask: writeDACL, AceType: "ACCESS_DENIED"},
		},
	}

	findings := NewGPOLinkPoisoningDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (a DENY ACE must not count as a dangerous grant)", findings[0].Count)
	}
}

// An ALLOW grant with a dangerous bit on the Policies container is still
// caught - the fix must not silence real positives.
func TestGPOLinkPoisoning_AllowACEStillCounts(t *testing.T) {
	const writeDACL = 0x00040000
	containerDN := "CN=Policies,CN=System,DC=test,DC=local"

	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: containerDN, Trustee: "S-1-5-21-1-2-3-1234", AccessMask: writeDACL, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewGPOLinkPoisoningDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (a real ALLOW grant must still be caught)", findings[0].Count)
	}
}
