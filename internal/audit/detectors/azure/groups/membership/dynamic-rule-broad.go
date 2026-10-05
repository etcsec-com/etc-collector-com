package membership

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DynamicRuleBroadDetector checks for groups with broad dynamic membership rules
type DynamicRuleBroadDetector struct {
	audit.BaseDetector
}

// NewDynamicRuleBroadDetector creates a new detector
func NewDynamicRuleBroadDetector() *DynamicRuleBroadDetector {
	return &DynamicRuleBroadDetector{
		BaseDetector: audit.NewBaseDetector("AZ_GROUP_DYNAMIC_RULE_BROAD", audit.CategoryGroups),
	}
}

// isDynamicMembershipGroup reports whether the group is actually a dynamic-
// membership group, per Microsoft Graph's group.groupTypes (Microsoft Learn,
// "groupType resource type", learn.microsoft.com/en-us/graph/api/resources/
// group; "DynamicMembership" is added to groupTypes when membershipRule is
// set and processing is enabled). A group with 0 static members targeted by
// this check but no dynamic rule at all is not what "Broad Dynamic Rules"
// claims to detect.
func isDynamicMembershipGroup(group types.Group) bool {
	for _, gt := range group.AzureGroupTypes {
		if gt == "DynamicMembership" {
			return true
		}
	}
	return false
}

// Detect executes the detection
func (d *DynamicRuleBroadDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group

	// The >100 cutoff is an etc-collector product heuristic, not a Microsoft-
	// or CIS-sourced limit - Microsoft's dynamic-membership-rule docs
	// (learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-
	// membership, learn.microsoft.com/en-us/entra/identity/users/
	// groups-create-rule) define rule syntax and a 15,000-dynamic-groups-per-
	// tenant ceiling, but no numeric "broad membership" threshold. This is a
	// volume-based repere flagging dynamic groups worth reviewing, not a
	// documented compliance requirement.
	for _, group := range data.Groups {
		if !isDynamicMembershipGroup(group) {
			continue
		}
		totalMembers := len(group.Members) + len(group.Member)
		if totalMembers > 100 {
			affected = append(affected, group)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Groups with Broad Dynamic Rules",
		Description: "Dynamic groups with broad membership rules may include unintended users.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDynamicRuleBroadDetector())
}
