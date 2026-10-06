package authmethods

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDVoice       = "AUTH_METHODS_VOICE_ENABLED"
	CategoryVoice = audit.CategoryIdentity
)

// VoiceDetector checks if voice call authentication is enabled
type VoiceDetector struct {
	audit.BaseDetector
}

// NewVoiceEnabledDetector creates a new voice enabled detector
func NewVoiceEnabledDetector() *VoiceDetector {
	return &VoiceDetector{
		BaseDetector: audit.NewBaseDetector(IDVoice, CategoryVoice),
	}
}

// Detect checks if voice call is enabled as an authentication method
func (d *VoiceDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDVoice,
		Severity:    types.SeverityLow,
		Category:    string(CategoryVoice),
		Title:       "Voice Call Authentication Enabled",
		Description: "Voice call is enabled as an authentication method. Voice calls can be forwarded or intercepted.",
		Count:       0,
	}

	if data.AzureAuthMethodsPolicy == nil {
		return []types.Finding{finding}
	}

	// Voice call MFA is confirmed weak by Microsoft itself, not just an
	// etc-collector opinion: "SMS and voice are no longer positioned as
	// secure authentication methods" (Microsoft Learn, "Passkeys by default
	// and retirement of Microsoft-provided SMS and voice authentication",
	// learn.microsoft.com/en-us/entra/identity/authentication/
	// concept-sms-voice-retirement). Microsoft-provided voice/SMS delivery
	// is scheduled for retirement 2027-02-01 for exactly this reason.
	if data.AzureAuthMethodsPolicy.PhoneVoice.State == "enabled" {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewVoiceEnabledDetector())
}
