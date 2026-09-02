package secrets

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDAppMultipleSecrets       = "APP_MULTIPLE_SECRETS"
	CategoryAppMultipleSecrets = audit.CategoryApplications
)

type AppMultipleSecretsDetector struct {
	audit.BaseDetector
}

func NewAppMultipleSecretsDetector() *AppMultipleSecretsDetector {
	return &AppMultipleSecretsDetector{
		BaseDetector: audit.NewBaseDetector(IDAppMultipleSecrets, CategoryAppMultipleSecrets),
	}
}

func (d *AppMultipleSecretsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedApps []types.AppRegistration
	now := data.Now

	for _, app := range data.AzureAppRegistrations {
		activeCount := 0
		for _, cred := range app.PasswordCredentials {
			if cred.EndDate.After(now) {
				activeCount++
			}
		}

		if activeCount > 2 {
			affectedApps = append(affectedApps, app)
		}
	}

	finding := types.Finding{
		Type:        IDAppMultipleSecrets,
		Severity:    types.SeverityMedium,
		Category:    string(CategoryAppMultipleSecrets),
		Title:       "Applications with Multiple Active Secrets",
		Description: "Applications with more than 2 active password credentials. Multiple secrets suggest poor rotation. Remove unused credentials and implement proper rotation with max 2 active secrets.",
		Count:       len(affectedApps),
	}

	if data.IncludeDetails && len(affectedApps) > 0 {
		finding.AffectedEntities = helpers.ToAffectedAppEntities(affectedApps)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAppMultipleSecretsDetector())
}
