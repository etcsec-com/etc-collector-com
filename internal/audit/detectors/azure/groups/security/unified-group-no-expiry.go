package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// UnifiedGroupNoExpiryDetector checks for Microsoft 365 groups without expiry
type UnifiedGroupNoExpiryDetector struct {
	audit.BaseDetector
}

// NewUnifiedGroupNoExpiryDetector creates a new detector
func NewUnifiedGroupNoExpiryDetector() *UnifiedGroupNoExpiryDetector {
	return &UnifiedGroupNoExpiryDetector{
		BaseDetector: audit.NewBaseDetector("AZ_GROUP_UNIFIED_NO_EXPIRY", audit.CategoryGroups),
	}
}

// isUnifiedGroup reports whether the group is a Microsoft 365 (Unified) group,
// per Microsoft Graph's group.groupTypes containing "Unified".
func isUnifiedGroup(group types.Group) bool {
	for _, gt := range group.AzureGroupTypes {
		if gt == "Unified" {
			return true
		}
	}
	return false
}

// Detect executes the detection
//
// Reads the tenant's group expiration policy from GET /groupLifecyclePolicies
// (collected once into data.AzureTenantConfig by the provider, not per-group).
// A policy only protects M365 groups tenant-wide when it exists AND its
// managedGroupTypes is "All" - "Selected" covers an explicit subset this
// detector has no way to resolve per-group, so it is treated the same as "no
// covering policy" rather than assumed compliant.
func (d *UnifiedGroupNoExpiryDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.AzureTenantConfig == nil || data.AzureTenantConfig.GroupLifecyclePolicyExists == nil {
		return []types.Finding{{
			Type:     d.ID(),
			Severity: types.SeverityInfo,
			Category: string(d.Category()),
			Title:    "Microsoft 365 Groups Without Expiry - not determinable (data not probed)",
			Description: "This check was NOT performed: GET /groupLifecyclePolicies was never probed " +
				"this audit (missing scope, or the run failed before this collection step - see " +
				"audit.warnings). This is not a compliance verdict either way.",
			Count: 1,
		}}
	}

	covered := *data.AzureTenantConfig.GroupLifecyclePolicyExists &&
		data.AzureTenantConfig.GroupLifecyclePolicyManagedGroupTypes == "All"

	var affected []types.Group
	if !covered {
		for _, group := range data.Groups {
			if isUnifiedGroup(group) {
				affected = append(affected, group)
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Microsoft 365 Groups Without Expiry",
		Description: "M365 groups without expiration policy may accumulate unused groups over time.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUnifiedGroupNoExpiryDetector())
}
