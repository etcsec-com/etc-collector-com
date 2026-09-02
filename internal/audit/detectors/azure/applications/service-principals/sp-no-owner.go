package serviceprincipals

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDSPNoOwner       = "SP_NO_OWNER"
	CategorySPNoOwner = audit.CategoryApplications
)

type SPNoOwnerDetector struct {
	audit.BaseDetector
}

func NewSPNoOwnerDetector() *SPNoOwnerDetector {
	return &SPNoOwnerDetector{
		BaseDetector: audit.NewBaseDetector(IDSPNoOwner, CategorySPNoOwner),
	}
}

func (d *SPNoOwnerDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedSPs []types.ServicePrincipal

	for _, sp := range data.AzureServicePrincipals {
		if sp.ServicePrincipalType == "Application" && len(sp.Owners) == 0 {
			affectedSPs = append(affectedSPs, sp)
		}
	}

	finding := types.Finding{
		Type:        IDSPNoOwner,
		Severity:    types.SeverityMedium,
		Category:    string(CategorySPNoOwner),
		Title:       "Service Principals Without Owner",
		Description: "Service principals without assigned owners cannot be properly managed. Assign owners to these service principals to ensure proper lifecycle management.",
		Count:       len(affectedSPs),
	}

	if data.IncludeDetails && len(affectedSPs) > 0 {
		finding.AffectedEntities = helpers.ToAffectedServicePrincipalEntities(affectedSPs)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSPNoOwnerDetector())
}
