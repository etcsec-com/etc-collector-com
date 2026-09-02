package registrations

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDAppUnused90Days       = "APP_UNUSED_90_DAYS"
	CategoryAppUnused90Days = audit.CategoryApplications
)

type AppUnused90DaysDetector struct {
	audit.BaseDetector
}

func NewAppUnused90DaysDetector() *AppUnused90DaysDetector {
	return &AppUnused90DaysDetector{
		BaseDetector: audit.NewBaseDetector(IDAppUnused90Days, CategoryAppUnused90Days),
	}
}

func (d *AppUnused90DaysDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedApps []types.AppRegistration
	ninetyDaysAgo := data.Now.AddDate(0, -3, 0)

	for _, app := range data.AzureAppRegistrations {
		if app.CreatedDateTime.Before(ninetyDaysAgo) {
			affectedApps = append(affectedApps, app)
		}
	}

	finding := types.Finding{
		Type:        IDAppUnused90Days,
		Severity:    types.SeverityMedium,
		Category:    string(CategoryAppUnused90Days),
		Title:       "Unused Application Registrations",
		Description: "Applications created more than 90 days ago that may not be actively used. Remove unused applications to reduce attack surface.",
		Count:       len(affectedApps),
	}

	if data.IncludeDetails && len(affectedApps) > 0 {
		finding.AffectedEntities = helpers.ToAffectedAppEntities(affectedApps)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAppUnused90DaysDetector())
}
