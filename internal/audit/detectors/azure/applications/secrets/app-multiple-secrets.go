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

		// The 2-active-secret threshold is an etc-collector heuristic, not a
		// general Microsoft rule. Microsoft does document a hard "Maximum of
		// two client secrets" cap (learn.microsoft.com/en-us/entra/
		// identity-platform/supported-accounts-validation, table row
		// "Client secrets (passwordCredentials)"), but it applies only to
		// signInAudience = AzureADandPersonalMicrosoftAccount /
		// PersonalMicrosoftAccount apps; org-only apps (AzureADMyOrg,
		// AzureADMultipleOrgs - the vast majority of tenant app
		// registrations) have "No limit". Flagging more than 2 active
		// secrets here is a local best-practice repere, not an official
		// compliance requirement for the apps this detector actually runs
		// against.
		if activeCount > 2 {
			affectedApps = append(affectedApps, app)
		}
	}

	finding := types.Finding{
		Type:        IDAppMultipleSecrets,
		Severity:    types.SeverityMedium,
		Category:    string(CategoryAppMultipleSecrets),
		Title:       "Applications with Multiple Active Secrets",
		Description: "Applications with more than 2 password credentials active at the same time. Concurrently active secrets expand the credential attack surface and make it harder to track which one is actually in use. Keep only the secrets needed for an in-progress rotation and remove the rest.",
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
