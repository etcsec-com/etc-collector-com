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
	// Verified against learn.microsoft.com/en-us/entra/identity-platform/
	// how-to-add-credentials: Microsoft's own stated recommendation is
	// "set an expiration value of less than 12 months" - it does not say
	// "6 months preferred". The 6-month threshold below is a stricter
	// etc-collector product choice, not a Microsoft-sourced figure; keep
	// the wording below honest about that distinction.
	sixMonthsFromNow := data.Now.AddDate(0, 6, 0)

	for _, app := range data.AzureAppRegistrations {
		hasLongExpiry := false
		for _, cred := range app.PasswordCredentials {
			if cred.EndDate.After(sixMonthsFromNow) {
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
		Description: "Application secrets configured to expire more than 6 months from now. Microsoft recommends secret lifetimes under 12 months; the 6-month threshold applied here is a stricter etc-collector best-practice repere, not itself a Microsoft-specified figure. Rotate to a shorter-lived secret and automate renewal.",
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
