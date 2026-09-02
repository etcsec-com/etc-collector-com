package secrets

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDAppSecretLongExpiry       = "APP_SECRET_LONG_EXPIRY"
	CategoryAppSecretLongExpiry = audit.CategoryApplications
)

type AppSecretLongExpiryDetector struct {
	audit.BaseDetector
}

func NewAppSecretLongExpiryDetector() *AppSecretLongExpiryDetector {
	return &AppSecretLongExpiryDetector{
		BaseDetector: audit.NewBaseDetector(IDAppSecretLongExpiry, CategoryAppSecretLongExpiry),
	}
}

func (d *AppSecretLongExpiryDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedApps []types.AppRegistration
	twoYearsFromNow := data.Now.AddDate(2, 0, 0)

	for _, app := range data.AzureAppRegistrations {
		hasLongExpiry := false
		for _, cred := range app.PasswordCredentials {
			if cred.EndDate.After(twoYearsFromNow) {
				hasLongExpiry = true
				break
			}
		}

		if hasLongExpiry {
			affectedApps = append(affectedApps, app)
		}
	}

	finding := types.Finding{
		Type:        IDAppSecretLongExpiry,
		Severity:    types.SeverityMedium,
		Category:    string(CategoryAppSecretLongExpiry),
		Title:       "Application Secrets with Long Expiry",
		Description: "Application secrets with expiry > 2 years. Long-lived secrets increase risk if compromised. Configure secrets to expire within 90-180 days and implement rotation.",
		Count:       len(affectedApps),
	}

	if data.IncludeDetails && len(affectedApps) > 0 {
		finding.AffectedEntities = helpers.ToAffectedAppEntities(affectedApps)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAppSecretLongExpiryDetector())
}
