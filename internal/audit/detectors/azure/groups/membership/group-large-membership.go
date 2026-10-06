package membership

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LargeMembershipDetector checks for groups with large membership
type LargeMembershipDetector struct {
	audit.BaseDetector
}

// NewLargeMembershipDetector creates a new detector
func NewLargeMembershipDetector() *LargeMembershipDetector {
	return &LargeMembershipDetector{
		BaseDetector: audit.NewBaseDetector("AZ_GROUP_LARGE_MEMBERSHIP", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *LargeMembershipDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group

	// Groups with more than 500 members are difficult to manage and audit
	for _, group := range data.Groups {
		totalMembers := len(group.Members) + len(group.Member)
		if totalMembers > 500 {
			affected = append(affected, group)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Groups with Large Membership",
		Description: "Groups with more than 500 members are difficult to manage and audit.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLargeMembershipDetector())
}
