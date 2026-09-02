package authmethods

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDWeakDefault       = "AUTH_METHODS_WEAK_DEFAULT"
	CategoryWeakDefault = audit.CategoryIdentity
)

// WeakDefaultDetector checks if weak default auth method is likely
type WeakDefaultDetector struct {
	audit.BaseDetector
}

// NewWeakDefaultMethodDetector creates a new weak default method detector
func NewWeakDefaultMethodDetector() *WeakDefaultDetector {
	return &WeakDefaultDetector{
		BaseDetector: audit.NewBaseDetector(IDWeakDefault, CategoryWeakDefault),
	}
}

// Detect checks if SMS or voice is likely the default MFA method
func (d *WeakDefaultDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDWeakDefault,
		Severity:    types.SeverityMedium,
		Category:    string(CategoryWeakDefault),
		Title:       "Weak Default Authentication Method",
		Description: "SMS or voice is likely the default MFA method as stronger methods are not enabled.",
		Count:       0,
	}

	if data.AzureAuthMethodsPolicy == nil {
		return []types.Finding{finding}
	}

	smsEnabled := data.AzureAuthMethodsPolicy.SMS.State == "enabled"
	voiceEnabled := data.AzureAuthMethodsPolicy.PhoneVoice.State == "enabled"
	authenticatorEnabled := data.AzureAuthMethodsPolicy.MicrosoftAuthenticator.State == "enabled"
	fido2Enabled := data.AzureAuthMethodsPolicy.FIDO2.State == "enabled"

	if (smsEnabled || voiceEnabled) && !authenticatorEnabled && !fido2Enabled {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWeakDefaultMethodDetector())
}
