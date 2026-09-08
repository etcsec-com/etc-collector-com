package permissions

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDAdminConsentNotRequired       = "APP_ADMIN_CONSENT_NOT_REQUIRED"
	CategoryAdminConsentNotRequired = audit.CategoryApplications
)

type AdminConsentNotRequiredDetector struct {
	audit.BaseDetector
}

func NewAdminConsentNotRequiredDetector() *AdminConsentNotRequiredDetector {
	return &AdminConsentNotRequiredDetector{
		BaseDetector: audit.NewBaseDetector(IDAdminConsentNotRequired, CategoryAdminConsentNotRequired),
	}
}

func (d *AdminConsentNotRequiredDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDAdminConsentNotRequired,
		Severity:    types.SeverityHigh,
		Category:    string(CategoryAdminConsentNotRequired),
		Title:       "Admin Consent Not Required for High-Privilege Permissions",
		Description: "Users can consent to application permissions without admin approval. Configure user consent settings to require admin approval for high-privilege permissions to prevent unauthorized app access.",
		Count:       0,
	}

	if data.AzureTenantConfig == nil {
		return []types.Finding{finding}
	}

	// nil means Graph's permissionGrantPoliciesAssigned could not be read: no verdict,
	// never guess. The built-in "legacy" policy lets users consent to ANY permission
	// (including high-privilege ones) without admin approval.
	for _, p := range data.AzureTenantConfig.UserConsentGrantPolicies {
		if strings.Contains(strings.ToLower(p), "legacy") {
			finding.Count = 1
			break
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminConsentNotRequiredDetector())
}
