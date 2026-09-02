package serviceprincipals

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDSPExternalOrganization       = "SP_EXTERNAL_ORGANIZATION"
	CategorySPExternalOrganization = audit.CategoryApplications
)

type SPExternalOrganizationDetector struct {
	audit.BaseDetector
}

func NewSPExternalOrganizationDetector() *SPExternalOrganizationDetector {
	return &SPExternalOrganizationDetector{
		BaseDetector: audit.NewBaseDetector(IDSPExternalOrganization, CategorySPExternalOrganization),
	}
}

func (d *SPExternalOrganizationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedSPs []types.ServicePrincipal

	for _, sp := range data.AzureServicePrincipals {
		if sp.ServicePrincipalType != "ManagedIdentity" && sp.AppOwnerOrganizationID != "" {
			affectedSPs = append(affectedSPs, sp)
		}
	}

	finding := types.Finding{
		Type:        IDSPExternalOrganization,
		Severity:    types.SeverityMedium,
		Category:    string(CategorySPExternalOrganization),
		Title:       "Service Principals from External Organizations",
		Description: "Service principals owned by external organizations have access to your tenant. Verify they require access to your tenant.",
		Count:       len(affectedSPs),
	}

	if data.IncludeDetails && len(affectedSPs) > 0 {
		finding.AffectedEntities = helpers.ToAffectedServicePrincipalEntities(affectedSPs)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSPExternalOrganizationDetector())
}
