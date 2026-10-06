package dangerous

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const uacTargetDN = "CN=srv01,OU=Servers,DC=contoso,DC=com"

// TestServerTrustAccount_PropertySetGrantFlagged pins the missing scope:
// the AD delegation wizard commonly grants "write account restrictions" at
// the User-Account-Restrictions property-set level
// (4c164200-20c0-11d0-a768-00aa006e0529), which per Microsoft's AD schema
// reference includes User-Account-Control as a member attribute. The
// detector used to check only the individual attribute's schemaIDGUID and
// missed every ACE written at the property-set level.
func TestServerTrustAccount_PropertySetGrantFlagged(t *testing.T) {
	nonAdminSID := "S-1-5-21-1-2-3-9001"

	data := &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   uacTargetDN,
				Trustee:    nonAdminSID,
				AceType:    "ACCESS_ALLOWED_OBJECT",
				AccessMask: types.MaskWriteProperty,
				ObjectType: "4c164200-20c0-11d0-a768-00aa006e0529",
			},
		},
	}

	findings := NewServerTrustAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: a WriteProperty grant on the User-Account-Restrictions property set covers userAccountControl", findings[0].Count)
	}
}

// TestServerTrustAccount_AttributeGrantStillFlagged guards the pre-existing
// path: a direct grant on the userAccountControl attribute's own GUID must
// still fire.
func TestServerTrustAccount_AttributeGrantStillFlagged(t *testing.T) {
	nonAdminSID := "S-1-5-21-1-2-3-9002"

	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   uacTargetDN,
				Trustee:    nonAdminSID,
				AceType:    "ACCESS_ALLOWED_OBJECT",
				AccessMask: types.MaskWriteProperty,
				ObjectType: "bf967a68-0de6-11d0-a285-00aa003049e2",
			},
		},
	}

	findings := NewServerTrustAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: direct userAccountControl attribute grant must still fire", findings[0].Count)
	}
}
