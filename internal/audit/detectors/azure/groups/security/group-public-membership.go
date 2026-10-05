package security

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PublicMembershipDetector checks for groups with public membership
type PublicMembershipDetector struct {
	audit.BaseDetector
}

// NewPublicMembershipDetector creates a new detector
func NewPublicMembershipDetector() *PublicMembershipDetector {
	return &PublicMembershipDetector{
		BaseDetector: audit.NewBaseDetector("AZ_GROUP_PUBLIC_MEMBERSHIP", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *PublicMembershipDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group

	// Public visibility (Graph: group.visibility == "Public") means any
	// tenant member can join the group without owner approval.
	for _, group := range data.Groups {
		if group.AzureVisibility != nil && strings.EqualFold(*group.AzureVisibility, "Public") {
			affected = append(affected, group)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Groups with Public Membership",
		Description: "Groups allowing any user to join without approval increase risk of unauthorized access.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPublicMembershipDetector())
}
