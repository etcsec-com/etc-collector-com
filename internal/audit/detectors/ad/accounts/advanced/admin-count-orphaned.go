package advanced

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminCountOrphanedDetector detects users with adminCount=1 but not in admin groups
type AdminCountOrphanedDetector struct {
	audit.BaseDetector
}

// NewAdminCountOrphanedDetector creates a new detector
func NewAdminCountOrphanedDetector() *AdminCountOrphanedDetector {
	return &AdminCountOrphanedDetector{
		BaseDetector: audit.NewBaseDetector("ADMIN_COUNT_ORPHANED", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *AdminCountOrphanedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Must have adminCount=true
		if !u.AdminCount {
			continue
		}

		// Check if actually in an admin group
		if len(u.MemberOf) == 0 {
			// adminCount but no group membership
			affected = append(affected, u)
			continue
		}

		// Check if in any admin group
		if !helpers.IsInAnyGroup(u.MemberOf, helpers.AdminGroups) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Orphaned AdminCount Flag",
		Description: "Accounts with adminCount=1 but not in any privileged group. This may indicate removed admins that still have residual privileges or SDProp protection.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Review these accounts. If no longer admins, clear adminCount flag and reset ACLs to allow proper inheritance.",
			"impact":         "Accounts may still have protected ACLs preventing proper management.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminCountOrphanedDetector())
}
