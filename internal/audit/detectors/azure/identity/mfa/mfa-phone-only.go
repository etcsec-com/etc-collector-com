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

// Detect checks if only SMS or voice are enabled without strong methods.
//
// Scope, precisely: this reads data.AzureAuthMethodsPolicy - the tenant-wide
// authentication methods POLICY (which methods are administratively
// enabled), not any individual user's actually-registered methods. A tenant
// where the title's condition holds means "an admin could still authenticate
// with phone-only", not "some specific user only has a phone registered".
//
// Source for the risk claim (not an invented one): NIST SP 800-63B-4
// formally classifies SMS/PSTN one-time passcodes as a "restricted
// authenticator" specifically for SIM-swap, SS7, and carrier
// social-engineering risk (pages.nist.gov/800-63-4/sp800-63b.html, §5.1.6.2
// "restricted authenticators"). Microsoft draws the same conclusion for its
// own tenants: SMS/voice are being retired precisely because they're "no
// longer positioned as secure authentication methods" (Microsoft Learn,
// "Passkeys by default and retirement of Microsoft-provided SMS and voice
// authentication", learn.microsoft.com/en-us/entra/identity/authentication/
// concept-sms-voice-retirement).
func (d *PhoneOnlyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:     IDPhoneOnly,
		Severity: types.SeverityMedium,
		Category: string(CategoryPhoneOnly),
		Title:    "Phone-Based MFA Methods Allowed Tenant-Wide (Policy)",
		Description: "The tenant's authentication methods policy allows phone-based methods (SMS, " +
			"voice) while no stronger method (Microsoft Authenticator, FIDO2) is enabled. This checks " +
			"the tenant-wide policy configuration, not any specific user's registered methods. " +
			"Phone-based methods are vulnerable to SIM-swapping and social engineering attacks " +
			"(NIST SP 800-63B-4 classifies SMS/voice OTP as a restricted authenticator for this reason).",
		Count: 0,
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
