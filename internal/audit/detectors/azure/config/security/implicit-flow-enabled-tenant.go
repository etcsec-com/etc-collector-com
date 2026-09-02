package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	AZ_IMPLICIT_FLOW_TENANT = "AZ_IMPLICIT_FLOW_TENANT"
)

type ImplicitFlowEnabledTenantDetector struct {
	audit.BaseDetector
}

func NewImplicitFlowEnabledTenantDetector() *ImplicitFlowEnabledTenantDetector {
	return &ImplicitFlowEnabledTenantDetector{
		BaseDetector: audit.NewBaseDetector(
			AZ_IMPLICIT_FLOW_TENANT,
			audit.CategoryConfig,
		),
	}
}

func (d *ImplicitFlowEnabledTenantDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Implicit Flow Allowed Tenant-Wide",
		Description: "OAuth implicit flow is not blocked at the tenant level. Implicit flow tokens are exposed in URLs.",
		Count:       1,
	}

	if data.IncludeDetails {
		finding.AffectedEntities = []types.AffectedEntity{
			{
				Type:        "tenant",
				DN:          "tenant",
				Name:        "Azure AD Tenant",
				Description: "OAuth implicit flow is not blocked tenant-wide",
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewImplicitFlowEnabledTenantDetector())
}
