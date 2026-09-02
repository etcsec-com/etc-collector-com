package standards

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	AZ_ENTITLEMENT_MANAGEMENT = "AZ_ENTITLEMENT_MANAGEMENT"
)

type EntitlementManagementDetector struct {
	audit.BaseDetector
}

func NewEntitlementManagementDetector() *EntitlementManagementDetector {
	return &EntitlementManagementDetector{
		BaseDetector: audit.NewBaseDetector(
			AZ_ENTITLEMENT_MANAGEMENT,
			audit.CategoryAzureCompliance,
		),
	}
}

// B_158/T_058 — used to fire unconditionally. data.AzureAccessPackagesProbed
// (v3.1.38 §1, GetEntitlementAccessPackagesCount against
// /identityGovernance/entitlementManagement/accessPackages) distinguishes
// "the endpoint couldn't be probed" from "probed and genuinely zero" — only
// the latter is a real finding.
//
// B_075/T_069 — "couldn't probe" and "probed, all clear" used to collapse
// into the same silent nil. Same fix as access-reviews-not-configured.go:
// an Info-severity finding when the probe never happened, visible in the
// report, zero-weight in the score.
func (d *EntitlementManagementDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if !data.AzureAccessPackagesProbed {
		return []types.Finding{{
			Type:     d.ID(),
			Severity: types.SeverityInfo,
			Category: string(d.Category()),
			Title:    "Entitlement Management Not Used — not determinable (data not probed)",
			Description: "This check was NOT performed: the entitlement management endpoint " +
				"(/identityGovernance/entitlementManagement/accessPackages) was never probed this " +
				"audit (missing scope, or the run failed before this collection step — see " +
				"audit.warnings). This is not a compliance verdict either way.",
			Count: 1,
		}}
	}
	if data.AzureAccessPackagesCount > 0 {
		return nil
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Entitlement Management Not Used",
		Description: "No entitlement management access packages configured for access governance.",
		Count:       1,
	}

	if data.IncludeDetails {
		finding.AffectedEntities = []types.AffectedEntity{
			{
				Type:        "tenant",
				DN:          "tenant",
				Name:        "Azure AD Tenant",
				Description: "Entitlement Management should be configured for access governance",
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewEntitlementManagementDetector())
}
