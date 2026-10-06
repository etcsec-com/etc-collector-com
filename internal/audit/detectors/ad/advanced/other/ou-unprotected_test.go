package other

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// acl_parser.go's aceTypeToString only ever emits "ACCESS_DENIED" or
// "ACCESS_DENIED_OBJECT" for a deny ACE - never "ACCESS_DENIED_ACE". The
// old comparison against "ACCESS_DENIED_ACE" therefore never matched
// anything, so protectedOUs stayed empty and every OU was reported
// unprotected regardless of a real Deny-Delete ACE for Everyone. This test
// fails against the old string (the protected OU is still reported as
// unprotected) and passes once the comparison targets "ACCESS_DENIED".
func TestOUUnprotected_RecognizesRealDenyDeleteACE(t *testing.T) {
	const deleteRight = 0x10000
	data := &audit.DetectorData{
		OUs: []types.OU{
			{DN: "OU=Protected,DC=test,DC=local"},
			{DN: "OU=Unprotected,DC=test,DC=local"},
		},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   "OU=Protected,DC=test,DC=local",
				Trustee:    "S-1-1-0",
				AccessMask: deleteRight,
				AceType:    "ACCESS_DENIED",
			},
		},
	}

	findings := NewOUUnprotectedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (only OU=Unprotected should be reported)", findings[0].Count)
	}
}
