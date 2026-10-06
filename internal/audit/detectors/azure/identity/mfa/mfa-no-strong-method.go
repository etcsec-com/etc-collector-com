package mfa

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDNoStrong       = "MFA_NO_STRONG_METHOD"
	CategoryNoStrong = audit.CategoryIdentity
)

// NoStrongMethodDetector checks if strong authentication methods are configured
type NoStrongMethodDetector struct {
	audit.BaseDetector
}

// NewMfaNoStrongMethodDetector creates a new no strong method detector
func NewMfaNoStrongMethodDetector() *NoStrongMethodDetector {
	return &NoStrongMethodDetector{
		BaseDetector: audit.NewBaseDetector(IDNoStrong, CategoryNoStrong),
	}
}

// Detect checks if Microsoft Authenticator or FIDO2 are enabled
func (d *NoStrongMethodDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDNoStrong,
		Severity:    types.SeverityHigh,
		Category:    string(CategoryNoStrong),
		Title:       "No Strong Authentication Method Configured",
		Description: "Neither Microsoft Authenticator nor FIDO2 security keys are enabled as authentication methods. SMS and voice are vulnerable to SIM-swapping.",
		Count:       0,
	}

	if data.AzureAuthMethodsPolicy == nil {
		return []types.Finding{finding}
	}

	authenticatorEnabled := data.AzureAuthMethodsPolicy.MicrosoftAuthenticator.State == "enabled"
	fido2Enabled := data.AzureAuthMethodsPolicy.FIDO2.State == "enabled"

	if !authenticatorEnabled && !fido2Enabled {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewMfaNoStrongMethodDetector())
}
