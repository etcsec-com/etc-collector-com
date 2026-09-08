package passwordpolicy

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDBannedPasswords       = "CUSTOM_BANNED_PASSWORDS_DISABLED"
	CategoryBannedPasswords = audit.CategoryIdentity
)

// BannedPasswordsDetector checks if custom banned password list is configured
type BannedPasswordsDetector struct {
	audit.BaseDetector
}

// NewCustomBannedPasswordsDetector creates a new custom banned passwords detector
func NewCustomBannedPasswordsDetector() *BannedPasswordsDetector {
	return &BannedPasswordsDetector{
		BaseDetector: audit.NewBaseDetector(IDBannedPasswords, CategoryBannedPasswords),
	}
}

// Detect checks if custom banned password list is configured
func (d *BannedPasswordsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDBannedPasswords,
		Severity:    types.SeverityHigh,
		Category:    string(CategoryBannedPasswords),
		Title:       "Custom Banned Password List Not Configured",
		Description: "No custom banned password list is configured in Azure AD Password Protection.",
		Count:       0,
	}

	// Source: "Configure custom Microsoft Entra password protection lists"
	// (learn.microsoft.com/en-us/entra/identity/authentication/tutorial-
	// configure-custom-password-protection). The custom banned password list
	// is stored as the BannedPasswordList value of the tenant's "Password
	// Rule Settings" directorySetting (Graph groupSettings, templateId
	// 5cf42378-d67d-4f36-ba46-e8b86229381d) - there is no dedicated Graph
	// resource for it. Count is 1 only when the tenant config was actually
	// collected AND that value is empty/unset (never configured).
	if data.AzureTenantConfig != nil && !data.AzureTenantConfig.CustomBannedPasswordListConfigured {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCustomBannedPasswordsDetector())
}
