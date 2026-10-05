package passwordpolicy

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDProtection       = "PASSWORD_PROTECTION_DISABLED"
	CategoryProtection = audit.CategoryIdentity
)

// ProtectionDetector checks if Azure AD Password Protection is enabled
type ProtectionDetector struct {
	audit.BaseDetector
}

// NewPasswordProtectionDisabledDetector creates a new password protection detector
func NewPasswordProtectionDisabledDetector() *ProtectionDetector {
	return &ProtectionDetector{
		BaseDetector: audit.NewBaseDetector(IDProtection, CategoryProtection),
	}
}

// Detect checks if Azure AD Password Protection is enabled
func (d *ProtectionDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDProtection,
		Severity:    types.SeverityHigh,
		Category:    string(CategoryProtection),
		Title:       "Azure AD Password Protection Not Enabled",
		Description: "Azure AD Password Protection is not enabled. This feature blocks commonly used weak passwords.",
		Count:       0,
	}

	// Only fire when the tenant's Password Rule Settings directorySetting
	// was actually read AND it explicitly disables the banned-password
	// check. No setting present is Azure's own default (protection ON),
	// not evidence of a violation - see AzureTenantConfig.PasswordProtectionEnabled.
	if data.AzureTenantConfig != nil {
		if enabled := data.AzureTenantConfig.PasswordProtectionEnabled; enabled != nil && !*enabled {
			finding.Count = 1
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPasswordProtectionDisabledDetector())
}
