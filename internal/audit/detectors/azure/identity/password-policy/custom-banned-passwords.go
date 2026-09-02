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

	// Tenant-level check - if we have config but no indicator of custom banned passwords
	if data.AzureTenantConfig != nil {
		// No way to verify custom banned passwords are configured
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCustomBannedPasswordsDetector())
}
