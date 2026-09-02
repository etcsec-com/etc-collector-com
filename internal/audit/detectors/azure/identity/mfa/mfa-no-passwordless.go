package mfa

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDNoPasswordless       = "MFA_NO_PASSWORDLESS"
	CategoryNoPasswordless = audit.CategoryIdentity
)

// NoPasswordlessDetector checks if passwordless authentication is enabled
type NoPasswordlessDetector struct {
	audit.BaseDetector
}

// NewMfaNoPasswordlessDetector creates a new no passwordless detector
func NewMfaNoPasswordlessDetector() *NoPasswordlessDetector {
	return &NoPasswordlessDetector{
		BaseDetector: audit.NewBaseDetector(IDNoPasswordless, CategoryNoPasswordless),
	}
}

// Detect checks if FIDO2 or Microsoft Authenticator passwordless is enabled
func (d *NoPasswordlessDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDNoPasswordless,
		Severity:    types.SeverityMedium,
		Category:    string(CategoryNoPasswordless),
		Title:       "Passwordless Authentication Not Enabled",
		Description: "Neither FIDO2 nor Microsoft Authenticator passwordless sign-in is enabled. Passwordless methods eliminate password-based attack vectors.",
		Count:       0,
	}

	if data.AzureAuthMethodsPolicy == nil {
		return []types.Finding{finding}
	}

	fido2Enabled := data.AzureAuthMethodsPolicy.FIDO2.State == "enabled"
	authenticatorEnabled := data.AzureAuthMethodsPolicy.MicrosoftAuthenticator.State == "enabled"

	if !fido2Enabled && !authenticatorEnabled {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewMfaNoPasswordlessDetector())
}
