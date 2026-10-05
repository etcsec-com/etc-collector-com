package access

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminRoleDetector checks for guest users with administrative roles
type AdminRoleDetector struct {
	audit.BaseDetector
}

// NewAdminRoleDetector creates a new detector
func NewAdminRoleDetector() *AdminRoleDetector {
	return &AdminRoleDetector{
		BaseDetector: audit.NewBaseDetector("GUEST_ADMIN_ROLE", audit.CategoryGuestExternal),
	}
}

// Detect executes the detection
func (d *AdminRoleDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Join role assignments to users by UserPrincipalName - NOT PrincipalName,
	// which is a display name (see the identical bug class in
	// privileged-access/roles/admin-stale-account.go: RoleAssignment's own
	// UPN field, ra.UserPrincipalName, is the one that actually matches
	// User.UserPrincipalName).
	userByUPN := make(map[string]types.User, len(data.Users))
	for _, user := range data.Users {
		if upn := strings.ToLower(strings.TrimSpace(user.UserPrincipalName)); upn != "" {
			userByUPN[upn] = user
		}
	}

	var guestAdmins []types.User
	seen := make(map[string]bool)
	for _, ra := range data.AzureRoleAssignments {
		key := strings.ToLower(strings.TrimSpace(ra.UserPrincipalName))
		if key == "" || seen[key] {
			continue
		}
		user, ok := userByUPN[key]
		if !ok {
			continue
		}
		if user.AzureUserType == nil || *user.AzureUserType != "Guest" {
			continue
		}
		seen[key] = true
		guestAdmins = append(guestAdmins, user)
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Guest User with Administrative Role",
		Description: "External guest users have administrative directory roles. This is a critical security risk.",
		Count:       len(guestAdmins),
	}

	if data.IncludeDetails && len(guestAdmins) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(guestAdmins)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminRoleDetector())
}
