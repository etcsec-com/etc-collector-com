package permissions

import (
	"context"

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

	// If UserConsentPolicy is not restricted, users can consent without admin approval
	if data.AzureTenantConfig.UserConsentPolicy != "" && data.AzureTenantConfig.UserConsentPolicy != "Disabled" {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminConsentNotRequiredDetector())
}
