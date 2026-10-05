package size

import (
	"context"
	"sort"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ExcessiveMembersDetector checks for groups with excessive direct members
type ExcessiveMembersDetector struct {
	audit.BaseDetector
}

// NewExcessiveMembersDetector creates a new detector
func NewExcessiveMembersDetector() *ExcessiveMembersDetector {
	return &ExcessiveMembersDetector{
		BaseDetector: audit.NewBaseDetector("GROUP_EXCESSIVE_MEMBERS", audit.CategoryGroups),
	}
}

const excessiveThreshold = 100

// Detect executes the detection
func (d *ExcessiveMembersDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group

	for _, group := range data.Groups {
		memberCount := len(group.Member)
		if memberCount > excessiveThreshold {
			affected = append(affected, group)
		}
	}

	// Sort by member count (most members first)
	sort.Slice(affected, func(i, j int) bool {
		return len(affected[i].Member) > len(affected[j].Member)
	})

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Group with Excessive Members",
		Description: "Groups with more than 100 direct members. Large groups are difficult to audit and may grant unintended access.",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
		}

		// Build largest groups list (max 5)
		largestGroups := make([]map[string]interface{}, 0, 5)
		for i := 0; i < len(affected) && i < 5; i++ {
			name := affected[i].SAMAccountName
			if name == "" {
				name = affected[i].DistinguishedName
			}
			largestGroups = append(largestGroups, map[string]interface{}{
				"name":        name,
				"memberCount": len(affected[i].Member),
			})
		}

		finding.Details = map[string]interface{}{
			"threshold":      excessiveThreshold,
			"largestGroups":  largestGroups,
			"recommendation": "Review large groups and consider breaking into smaller, role-based groups for better access control.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewExcessiveMembersDetector())
}
