package sspr

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDMethodsWeak       = "SSPR_METHODS_WEAK"
	CategoryMethodsWeak = audit.CategoryIdentity
)

// MethodsWeakDetector checks if SSPR uses weak authentication methods
type MethodsWeakDetector struct {
	audit.BaseDetector
}

// NewSsprMethodsWeakDetector creates a new SSPR weak methods detector
func NewSsprMethodsWeakDetector() *MethodsWeakDetector {
	return &MethodsWeakDetector{
		BaseDetector: audit.NewBaseDetector(IDMethodsWeak, CategoryMethodsWeak),
	}
}

// Detect checks if SSPR uses weak methods (security questions, SMS)
func (d *MethodsWeakDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDMethodsWeak,
		Severity:    types.SeverityMedium,
		Category:    string(CategoryMethodsWeak),
		Title:       "Weak SSPR Authentication Methods",
		Description: "SSPR uses weak methods (security questions, SMS). Recommend app-based or FIDO2 methods.",
		Count:       0,
	}

	if data.AzureAuthMethodsPolicy == nil {
		return []types.Finding{finding}
	}

	// Check if weak methods are enabled but no strong methods
	smsEnabled := data.AzureAuthMethodsPolicy.SMS.State == "enabled"
	emailEnabled := data.AzureAuthMethodsPolicy.Email.State == "enabled"
	authenticatorEnabled := data.AzureAuthMethodsPolicy.MicrosoftAuthenticator.State == "enabled"
	fido2Enabled := data.AzureAuthMethodsPolicy.FIDO2.State == "enabled"

	if (smsEnabled || emailEnabled) && !authenticatorEnabled && !fido2Enabled {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSsprMethodsWeakDetector())
}
