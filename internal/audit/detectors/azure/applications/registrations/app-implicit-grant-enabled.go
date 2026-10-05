package registrations

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDAppImplicitGrantEnabled       = "APP_IMPLICIT_GRANT_ENABLED"
	CategoryAppImplicitGrantEnabled = audit.CategoryApplications
)

type AppImplicitGrantEnabledDetector struct {
	audit.BaseDetector
}

func NewAppImplicitGrantEnabledDetector() *AppImplicitGrantEnabledDetector {
	return &AppImplicitGrantEnabledDetector{
		BaseDetector: audit.NewBaseDetector(IDAppImplicitGrantEnabled, CategoryAppImplicitGrantEnabled),
	}
}

func (d *AppImplicitGrantEnabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedApps []types.AppRegistration

	for _, app := range data.AzureAppRegistrations {
		if app.ImplicitGrantEnabled {
			affectedApps = append(affectedApps, app)
		}
	}

	finding := types.Finding{
		Type:        IDAppImplicitGrantEnabled,
		Severity:    types.SeverityHigh,
		Category:    string(CategoryAppImplicitGrantEnabled),
		Title:       "Applications with Implicit Grant Flow",
		Description: "Applications using OAuth implicit grant flow. Implicit flow exposes tokens in the URL fragment. Migrate to authorization code flow with PKCE for better security.",
		Count:       len(affectedApps),
	}

	if data.IncludeDetails && len(affectedApps) > 0 {
		finding.AffectedEntities = helpers.ToAffectedAppEntities(affectedApps)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAppImplicitGrantEnabledDetector())
}
