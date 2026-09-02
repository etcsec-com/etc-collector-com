package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// OrphanedGroupsDetector checks for orphaned groups
type OrphanedGroupsDetector struct {
	audit.BaseDetector
}

// NewOrphanedGroupsDetector creates a new detector
func NewOrphanedGroupsDetector() *OrphanedGroupsDetector {
	return &OrphanedGroupsDetector{
		BaseDetector: audit.NewBaseDetector("AZ_GROUP_ORPHANED", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *OrphanedGroupsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group

	// Groups with no members and no membership in other groups
	for _, group := range data.Groups {
		totalMembers := len(group.Members) + len(group.Member)
		if totalMembers == 0 && len(group.MemberOf) == 0 {
			affected = append(affected, group)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Orphaned Groups",
		Description: "Groups with no members and no membership in other groups may be abandoned.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewOrphanedGroupsDetector())
}
