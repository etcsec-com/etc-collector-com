package permissions

import (
	"context"
	"strings"

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

	// nil means Graph's permissionGrantPoliciesAssigned could not be read: no verdict,
	// never guess. A non-nil empty slice means consent to apps is disabled (safe).
	if data.AzureTenantConfig.UserConsentGrantPolicies == nil {
		return []types.Finding{finding}
	}
	for _, p := range data.AzureTenantConfig.UserConsentGrantPolicies {
		if strings.Contains(strings.ToLower(p), "legacy") {
			finding.Count = 1
			break
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUserConsentUnrestrictedDetector())
}
