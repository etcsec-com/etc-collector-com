package audit

import "github.com/etcsec-com/etc-collector/pkg/types"

// BuildCrossTenantAccessSummary composes the default policy + partner list +
// multi-tenant-org config into the single audit.crossTenantAccess payload.
//
// Returns nil when all three sources are empty/nil so the JSON output skips
// the key entirely (omitempty on AuditReport.CrossTenantAccess) — avoids
// an empty {} object cluttering the report on tenants where the collector
// couldn't read any of the cross-tenant endpoints.
func BuildCrossTenantAccessSummary(
	def *types.CrossTenantDefaultPolicy,
	partners []types.CrossTenantPartnerPolicy,
	mto *types.CrossTenantMultiTenantOrg,
) *types.CrossTenantAccessSummary {
	if def == nil && len(partners) == 0 && mto == nil {
		return nil
	}
	return &types.CrossTenantAccessSummary{
		Default:                 def,
		Partners:                partners,
		MultiTenantOrganization: mto,
	}
}
