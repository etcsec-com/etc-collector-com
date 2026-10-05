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

// Detect checks if only weak (SMS/voice) methods are enabled tenant-wide,
// with no stronger alternative available for users to register or be
// steered to. Microsoft Graph's authenticationMethodsPolicy has no "default
// method" concept for this to observe directly (there's no such property on
// the policy resource: learn.microsoft.com/en-us/graph/api/resources/
// authenticationmethodspolicy) - a per-user "preferred/default sign-in
// method" is a runtime registration detail, not a tenant policy setting.
// This only ever checks method-enablement state, so the title and
// description below must say exactly that instead of claiming to observe an
// actual default.
func (d *WeakDefaultDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDWeakDefault,
		Severity:    types.SeverityMedium,
		Category:    string(CategoryWeakDefault),
		Title:       "Only Weak Authentication Methods Enabled",
		Description: "SMS or voice is enabled while Microsoft Authenticator and FIDO2 are both disabled, leaving no stronger method for users to register or fall back to. This does not observe an actual per-user default sign-in method - Microsoft Graph's authentication methods policy has no such setting to check.",
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
