package moderate

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	fcpUserDN       = "CN=Akira Jackson,OU=IT,DC=example,DC=com"
	fcpGUID         = "00299570-246d-11d0-a768-00aa006e0529"
	fcpOrdinaryUser = "S-1-5-21-1234567890-1111111111-2222222222-1105"
	fcpBuiltinAdmin = "S-1-5-32-544"
)

func fcpData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		ObjectByDN: map[string]*audit.ObjectMeta{
			fcpUserDN: {DN: fcpUserDN, Name: "Akira Jackson", EntityType: types.EntityTypeUser},
		},
	}
}

func fcpDetect(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewUserForceChangePasswordDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

func TestUserForceChangePassword_FiltersDenyAndBuiltinAdmins(t *testing.T) {
	t.Run("DENY ace does NOT fire", func(t *testing.T) {
		f := fcpDetect(t, fcpData(
			types.ACLEntry{ObjectDN: fcpUserDN, Trustee: fcpOrdinaryUser, ObjectType: fcpGUID, AceType: "ACCESS_DENIED"},
		))
		if f.Count != 0 {
			t.Fatalf("a DENY ace grants nothing, got count=%d", f.Count)
		}
	})

	t.Run("builtin admin trustee does NOT fire", func(t *testing.T) {
		f := fcpDetect(t, fcpData(
			types.ACLEntry{ObjectDN: fcpUserDN, Trustee: fcpBuiltinAdmin, ObjectType: fcpGUID, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("built-in admins hold this right by construction, got count=%d", f.Count)
		}
	})

	t.Run("ordinary user grant DOES fire", func(t *testing.T) {
		f := fcpDetect(t, fcpData(
			types.ACLEntry{ObjectDN: fcpUserDN, Trustee: fcpOrdinaryUser, ObjectType: fcpGUID, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("a real delegation to a non-admin must fire, got count=%d", f.Count)
		}
		if len(f.AffectedEntities) != 1 {
			t.Fatalf("finding must be actionable, got %d entities", len(f.AffectedEntities))
		}
	})
}
