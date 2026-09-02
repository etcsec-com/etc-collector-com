package roles

import (
	"context"
	"fmt"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminStaleAccountDetector checks for admin roles on stale user accounts
type AdminStaleAccountDetector struct {
	audit.BaseDetector
}

// NewAdminStaleAccountDetector creates a new detector
func NewAdminStaleAccountDetector() *AdminStaleAccountDetector {
	return &AdminStaleAccountDetector{
		BaseDetector: audit.NewBaseDetector("PA_ADMIN_STALE_ACCOUNT", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *AdminStaleAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	const staleThresholdDays = 90

	// Build map of user principals with last logon (using UPN as key for Azure users)
	userMap := make(map[string]types.User)
	for _, user := range data.Users {
		if user.UserPrincipalName != "" {
			userMap[user.UserPrincipalName] = user
		}
	}

	var staleAdminAssignments []types.RoleAssignment
	now := data.Now

	// Find admin role assignments to stale accounts
	// Note: This check works best when Azure AD data includes user lastSignIn info
	for _, ra := range data.AzureRoleAssignments {
		if !privilegedRoleIDs[ra.RoleID] {
			continue
		}

		// Try to match principal by name (PrincipalName should match UserPrincipalName)
		if user, ok := userMap[ra.PrincipalName]; ok {
			// Use Azure sign-in timestamps (primary), AD fallback
			var lastActivity time.Time
			if user.AzureLastSignInDateTime != nil && !user.AzureLastSignInDateTime.IsZero() {
				lastActivity = *user.AzureLastSignInDateTime
			}
			if user.AzureLastNonInteractiveSignInDateTime != nil && !user.AzureLastNonInteractiveSignInDateTime.IsZero() {
				if lastActivity.IsZero() || user.AzureLastNonInteractiveSignInDateTime.After(lastActivity) {
					lastActivity = *user.AzureLastNonInteractiveSignInDateTime
				}
			}
			if lastActivity.IsZero() && !user.LastLogon.IsZero() {
				lastActivity = user.LastLogon
			}
			if !lastActivity.IsZero() {
				daysSinceLastLogon := int(now.Sub(lastActivity).Hours() / 24)
				if daysSinceLastLogon >= staleThresholdDays {
					staleAdminAssignments = append(staleAdminAssignments, ra)
				}
			}
		}
	}

	count := len(staleAdminAssignments)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Stale Administrative Accounts",
		Description: fmt.Sprintf("Admin role assignments to users who haven't signed in for %d+ days. Found %d stale administrative assignments. Review and remove unused privileged access.", staleThresholdDays, count),
		Count:       count,
	}

	if count > 0 {
		finding.AffectedEntities = helpers.ToAffectedRoleAssignmentEntities(staleAdminAssignments)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminStaleAccountDetector())
}
