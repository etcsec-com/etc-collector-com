package other

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestSIDHistoryWellKnown_FiresOnBuiltinAdministratorsSID pins the missing
// RID fix: S-1-5-32-544 (BUILTIN\Administrators) is a classic SID-History
// injection target per Microsoft's well-known SIDs reference, but was
// absent from privilegedRIDs. This must fail against the old 8-entry list
// and pass now that "-544" is included.
func TestSIDHistoryWellKnown_FiresOnBuiltinAdministratorsSID(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{
				DN:             "CN=injected,OU=Users,DC=contoso,DC=com",
				SAMAccountName: "injected",
				SIDHistory:     []string{"S-1-5-32-544"},
			},
		},
	}

	findings := NewSIDHistoryWellKnownDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 for sIDHistory containing BUILTIN\\Administrators (S-1-5-32-544), got %d", findings[0].Count)
	}
}

// TestSIDHistoryWellKnown_UnprivilegedSIDDoesNotFire guards against
// over-matching: an ordinary, non-privileged SID must not fire.
func TestSIDHistoryWellKnown_UnprivilegedSIDDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{
				DN:             "CN=normal,OU=Users,DC=contoso,DC=com",
				SAMAccountName: "normal",
				SIDHistory:     []string{"S-1-5-21-1-2-3-9999"},
			},
		},
	}

	findings := NewSIDHistoryWellKnownDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 for a non-privileged SID, got %d", findings[0].Count)
	}
}
