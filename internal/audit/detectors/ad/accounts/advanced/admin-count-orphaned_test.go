package advanced

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Microsoft Learn, "Appendix C: Protected Accounts and Groups in Active
// Directory" (learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/
// security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
// lists krbtgt as a protected ACCOUNT (adminCount=1 on it is normal,
// AdminSDHolder/SDProp behavior, never an orphan) and names 13 protected
// GROUPS beyond the 8 this detector used to check. Before the fix, krbtgt
// was flagged as "orphaned" and a user whose adminCount=1 came only from
// membership in one of the five missing groups (Domain Controllers,
// Read-only Domain Controllers, Replicator, Key Admins, Enterprise Key
// Admins) was flagged too.
func TestAdminCountOrphaned_KrbtgtNeverFlagged(t *testing.T) {
	u := types.User{
		SAMAccountName: "krbtgt",
		AdminCount:     true,
		// No group membership at all - the case that used to guarantee a flag.
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("krbtgt is protected by design (Appendix C); it must never be flagged as orphaned, got Count=%d", f.Count)
	}
}

func TestAdminCountOrphaned_BuiltinAdministratorNeverFlagged(t *testing.T) {
	u := types.User{
		SAMAccountName: "Administrator",
		AdminCount:     true,
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("the built-in Administrator account is protected by design (Appendix C); it must never be flagged as orphaned, got Count=%d", f.Count)
	}
}

func TestAdminCountOrphaned_PreviouslyMissingProtectedGroups(t *testing.T) {
	cases := []struct {
		name  string
		group string
	}{
		{"Domain Controllers", "CN=Domain Controllers,CN=Users,DC=corp,DC=local"},
		{"Read-only Domain Controllers", "CN=Read-only Domain Controllers,CN=Users,DC=corp,DC=local"},
		{"Replicator", "CN=Replicator,CN=Builtin,DC=corp,DC=local"},
		{"Key Admins", "CN=Key Admins,CN=Users,DC=corp,DC=local"},
		{"Enterprise Key Admins", "CN=Enterprise Key Admins,CN=Users,DC=corp,DC=local"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := types.User{
				SAMAccountName: "svc-" + tc.name,
				AdminCount:     true,
				MemberOf:       []string{tc.group},
			}
			data := &audit.DetectorData{Users: []types.User{u}}

			f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("membership in %q (an Appendix C protected group) legitimately explains adminCount=1; must not be flagged as orphaned, got Count=%d", tc.name, f.Count)
			}
		})
	}
}

func TestAdminCountOrphaned_TrulyOrphanedStillFlagged(t *testing.T) {
	u := types.User{
		SAMAccountName: "former-admin",
		AdminCount:     true,
		MemberOf:       []string{"CN=Marketing,CN=Users,DC=corp,DC=local"},
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewAdminCountOrphanedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("adminCount=1 with only a non-protected group membership must still be flagged, got Count=%d", f.Count)
	}
}
