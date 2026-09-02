package secrets

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDAppSecretExpired       = "APP_SECRET_EXPIRED"
	CategoryAppSecretExpired = audit.CategoryApplications
)

type AppSecretExpiredDetector struct {
	audit.BaseDetector
}

func NewAppSecretExpiredDetector() *AppSecretExpiredDetector {
	return &AppSecretExpiredDetector{
		BaseDetector: audit.NewBaseDetector(IDAppSecretExpired, CategoryAppSecretExpired),
	}
}

func (d *AppSecretExpiredDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedApps []types.AppRegistration
	now := data.Now

	for _, app := range data.AzureAppRegistrations {
		hasExpired := false
		for _, cred := range app.PasswordCredentials {
			if cred.EndDate.Before(now) {
				hasExpired = true
				break
			}
		}

		if hasExpired {
			affectedApps = append(affectedApps, app)
		}
	}

	finding := types.Finding{
		Type:        IDAppSecretExpired,
		Severity:    types.SeverityHigh,
		Category:    string(CategoryAppSecretExpired),
		Title:       "Applications with Expired Secrets",
		Description: "Application credentials have expired. Expired secrets indicate abandoned or poorly maintained apps. Remove expired credentials or rotate if still in use.",
		Count:       len(affectedApps),
	}

	if data.IncludeDetails && len(affectedApps) > 0 {
		finding.AffectedEntities = helpers.ToAffectedAppEntities(affectedApps)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAppSecretExpiredDetector())
}
