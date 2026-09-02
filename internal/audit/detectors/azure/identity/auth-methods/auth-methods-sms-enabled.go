package authmethods

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	ID       = "AUTH_METHODS_SMS_ENABLED"
	Category = audit.CategoryIdentity
)

// SmsEnabledDetector checks if SMS authentication method is enabled
type SmsEnabledDetector struct {
	audit.BaseDetector
}

// NewSmsEnabledDetector creates a new SMS enabled detector
func NewSmsEnabledDetector() *SmsEnabledDetector {
	return &SmsEnabledDetector{
		BaseDetector: audit.NewBaseDetector(ID, Category),
	}
}

// Detect checks if SMS is enabled as an authentication method
func (d *SmsEnabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        ID,
		Severity:    types.SeverityMedium,
		Category:    string(Category),
		Title:       "SMS Authentication Method Enabled",
		Description: "SMS is enabled as an authentication method. SMS codes can be intercepted via SIM-swapping attacks.",
		Count:       0,
	}

	if data.AzureAuthMethodsPolicy == nil {
		return []types.Finding{finding}
	}

	if data.AzureAuthMethodsPolicy.SMS.State == "enabled" {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSmsEnabledDetector())
}
