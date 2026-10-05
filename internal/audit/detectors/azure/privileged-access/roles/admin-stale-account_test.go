package roles

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PA_ADMIN_STALE_ACCOUNT joined userMap (keyed by UserPrincipalName) against
// ra.PrincipalName - which Graph populates with the principal's DisplayName,
// not its UPN (client.go's getRoleAssignmentsWithPrincipal) - so the lookup
// essentially never hit.
func TestAdminStaleAccount_MatchesByUPN(t *testing.T) {
	var roleID string
	for id := range privilegedRoleIDs {
		roleID = id
		break
	}

	now := time.Now()
	staleSignIn := now.AddDate(0, 0, -120)

	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				UserPrincipalName:       "carol@contoso.com",
				AzureLastSignInDateTime: &staleSignIn,
			},
		},
		AzureRoleAssignments: []types.RoleAssignment{
			{
				RoleID:            roleID,
				PrincipalName:     "Carol Admin", // display name, deliberately NOT the UPN
				UserPrincipalName: "carol@contoso.com",
			},
		},
	}

	f := NewAdminStaleAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 stale admin assignment matched via UPN, got %d", f.Count)
	}
}
