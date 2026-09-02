package mfa

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDPhoneOnly       = "MFA_PHONE_ONLY"
	CategoryPhoneOnly = audit.CategoryIdentity
)

// PhoneOnlyDetector checks if only phone-based MFA methods are enabled
type PhoneOnlyDetector struct {
	audit.BaseDetector
}

// NewMfaPhoneOnlyDetector creates a new phone-only MFA detector
func NewMfaPhoneOnlyDetector() *PhoneOnlyDetector {
	return &PhoneOnlyDetector{
		BaseDetector: audit.NewBaseDetector(IDPhoneOnly, CategoryPhoneOnly),
	}
}

// Detect checks if only SMS or voice are enabled without strong methods
func (d *PhoneOnlyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDPhoneOnly,
		Severity:    types.SeverityMedium,
		Category:    string(CategoryPhoneOnly),
		Title:       "Phone-Based MFA Methods Only",
		Description: "Only phone-based methods (SMS, voice) are enabled. These are vulnerable to SIM-swapping and social engineering attacks.",
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
	audit.MustRegister(NewMfaPhoneOnlyDetector())
}
