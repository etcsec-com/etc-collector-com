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
//
// Known limitation (non vu, not fixable in this detector alone): MemberOf is
// never populated for Azure AD groups by the collector (internal/providers/
// azure/client.go has no code path that assigns it - only the AD-side group
// conversion sets it), so the "not a member of any other group" half of this
// condition is always vacuously true today and contributes nothing to the
// result. It is kept for when the collector gains that field rather than
// removed, so this check tightens automatically instead of silently staying
// member-count-only forever. Fixing the collection gap needs a client.go
// change, out of this detector's scope.
//
// "Orphaned" here means the narrower, distinct notion of "has no members" -
// group-orphaned.go does NOT check ownership. A group missing an owner is
// group-no-owner.go's territory (AZ_GROUP_NO_OWNER); the two are unrelated
// conditions that can each hold independently of the other.
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
		Title:       "Empty Groups (No Members)",
		Description: "Groups with no members (and, where collected, no membership in any other group) may be abandoned. Distinct from ownerless groups - see AZ_GROUP_NO_OWNER for groups missing an owner.",
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
