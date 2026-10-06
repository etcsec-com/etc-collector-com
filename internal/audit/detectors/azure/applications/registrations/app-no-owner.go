package registrations

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDAppNoOwner       = "APP_NO_OWNER"
	CategoryAppNoOwner = audit.CategoryApplications
)

type AppNoOwnerDetector struct {
	audit.BaseDetector
}

func NewAppNoOwnerDetector() *AppNoOwnerDetector {
	return &AppNoOwnerDetector{
		BaseDetector: audit.NewBaseDetector(IDAppNoOwner, CategoryAppNoOwner),
	}
}

func (d *AppNoOwnerDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedApps []types.AppRegistration

	for _, app := range data.AzureAppRegistrations {
		if len(app.Owners) == 0 {
			affectedApps = append(affectedApps, app)
		}
	}

	finding := types.Finding{
		Type:        IDAppNoOwner,
		Severity:    types.SeverityHigh,
		Category:    string(CategoryAppNoOwner),
		Title:       "Applications Without Owner",
		Description: "Application registrations without an assigned owner. Orphaned apps cannot be managed. Assign owners to these applications as orphaned applications pose security and compliance risks.",
		Count:       len(affectedApps),
	}

	if data.IncludeDetails && len(affectedApps) > 0 {
		finding.AffectedEntities = helpers.ToAffectedAppEntities(affectedApps)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAppNoOwnerDetector())
}
