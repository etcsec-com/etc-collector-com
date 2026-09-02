package authmethods

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDEmailOTP       = "AUTH_METHODS_EMAIL_OTP_ENABLED"
	CategoryEmailOTP = audit.CategoryIdentity
)

// EmailOTPDetector checks if email OTP authentication is enabled
type EmailOTPDetector struct {
	audit.BaseDetector
}

// NewEmailOtpDetector creates a new email OTP detector
func NewEmailOtpDetector() *EmailOTPDetector {
	return &EmailOTPDetector{
		BaseDetector: audit.NewBaseDetector(IDEmailOTP, CategoryEmailOTP),
	}
}

// Detect checks if email OTP is enabled as an authentication method
func (d *EmailOTPDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDEmailOTP,
		Severity:    types.SeverityLow,
		Category:    string(CategoryEmailOTP),
		Title:       "Email OTP Authentication Enabled",
		Description: "Email one-time password is enabled. If the email account is compromised, OTP codes are also compromised.",
		Count:       0,
	}

	if data.AzureAuthMethodsPolicy == nil {
		return []types.Finding{finding}
	}

	if data.AzureAuthMethodsPolicy.Email.State == "enabled" {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewEmailOtpDetector())
}
