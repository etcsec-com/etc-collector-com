package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GuestInSecurityGroupDetector checks for guest users in security groups
type GuestInSecurityGroupDetector struct {
	audit.BaseDetector
}

// NewGuestInSecurityGroupDetector creates a new detector
func NewGuestInSecurityGroupDetector() *GuestInSecurityGroupDetector {
	return &GuestInSecurityGroupDetector{
		BaseDetector: audit.NewBaseDetector("AZ_GROUP_GUEST_IN_SECURITY", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *GuestInSecurityGroupDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group

	// A security group with a guest (external) member count above zero is a
	// real, measured signal: the provider already resolves it per-group via
	// /groups/{id}/members/$count?$filter=userType eq 'Guest'.
	for _, group := range data.Groups {
		if group.AzureSecurityEnabled == nil || !*group.AzureSecurityEnabled {
			continue
		}
		if group.AzureExternalMembersCount != nil && *group.AzureExternalMembersCount > 0 {
			affected = append(affected, group)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Guest Users in Security Groups",
		Description: "External guest users are members of security groups, potentially gaining access to internal resources.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewGuestInSecurityGroupDetector())
}
