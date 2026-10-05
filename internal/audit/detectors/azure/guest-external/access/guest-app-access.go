package access

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AppAccessUnrestrictedDetector checks if guest application access is unrestricted
type AppAccessUnrestrictedDetector struct {
	audit.BaseDetector
}

// NewAppAccessUnrestrictedDetector creates a new detector
func NewAppAccessUnrestrictedDetector() *AppAccessUnrestrictedDetector {
	return &AppAccessUnrestrictedDetector{
		BaseDetector: audit.NewBaseDetector("GUEST_APP_ACCESS_UNRESTRICTED", audit.CategoryGuestExternal),
	}
}

// Detect executes the detection
func (d *AppAccessUnrestrictedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Source: Microsoft Graph "authorizationPolicy resource type"
	// (learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy):
	// "guestUserRoleId ... Currently following roles are supported: User
	// (a0b1b346-4d3e-4e8b-98f8-753987be4970), Guest User
	// (10dae51f-b6af-4016-8d66-8c2a99b929b3), and Restricted Guest User
	// (2af84b1e-32c8-42b7-82bc-daa82404023b)." Only the "User" templateId
	// (types.AzureGuestRoleUnrestrictedUser) grants guests the same access as
	// members, including unrestricted application access - "Guest User" is
	// Microsoft's recommended, more restrictive default.
	// authorizationPolicy.guestUserRoleId is already collected by
	// GetAuthorizationPolicy and wired into data.AzureAuthorizationPolicy.
	if data.AzureAuthorizationPolicy == nil || data.AzureAuthorizationPolicy.GuestUserRoleID == "" {
		// Policy could not be probed this run - no verdict either way.
		return nil
	}

	count := 0
	if strings.EqualFold(data.AzureAuthorizationPolicy.GuestUserRoleID, types.AzureGuestRoleUnrestrictedUser) {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Guest Application Access Unrestricted",
		Description: "Guest users are assigned the \"User\" role (guestUserRoleId), granting the same application access as regular members.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAppAccessUnrestrictedDetector())
}
