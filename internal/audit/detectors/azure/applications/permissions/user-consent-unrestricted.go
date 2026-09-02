package permissions

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDUserConsentUnrestricted       = "APP_USER_CONSENT_UNRESTRICTED"
	CategoryUserConsentUnrestricted = audit.CategoryApplications
)

type UserConsentUnrestrictedDetector struct {
	audit.BaseDetector
}

func NewUserConsentUnrestrictedDetector() *UserConsentUnrestrictedDetector {
	return &UserConsentUnrestrictedDetector{
		BaseDetector: audit.NewBaseDetector(IDUserConsentUnrestricted, CategoryUserConsentUnrestricted),
	}
}

func (d *UserConsentUnrestrictedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDUserConsentUnrestricted,
		Severity:    types.SeverityCritical,
		Category:    string(CategoryUserConsentUnrestricted),
		Title:       "User Consent Unrestricted",
		Description: "Users can consent to any application requesting permissions. This enables consent phishing attacks. Disable user consent or restrict it to verified publishers and specific permissions to prevent consent phishing attacks.",
		Count:       0,
	}

	if data.AzureTenantConfig == nil {
		return []types.Finding{finding}
	}

	// If UserConsentPolicy is empty or allows all, users can consent to any application
	if data.AzureTenantConfig.UserConsentPolicy == "" || data.AzureTenantConfig.UserConsentPolicy == "EnabledForAll" {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUserConsentUnrestrictedDetector())
}
