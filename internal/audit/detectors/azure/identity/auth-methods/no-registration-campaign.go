package authmethods

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDNoRegistration       = "AUTH_METHODS_NO_REGISTRATION"
	CategoryNoRegistration = audit.CategoryIdentity
)

// NoRegistrationDetector checks if auth method registration enforcement is enabled
type NoRegistrationDetector struct {
	audit.BaseDetector
}

// NewNoRegistrationCampaignDetector creates a new no registration detector
func NewNoRegistrationCampaignDetector() *NoRegistrationDetector {
	return &NoRegistrationDetector{
		BaseDetector: audit.NewBaseDetector(IDNoRegistration, CategoryNoRegistration),
	}
}

// Detect checks if registration enforcement is enabled
func (d *NoRegistrationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDNoRegistration,
		Severity:    types.SeverityMedium,
		Category:    string(CategoryNoRegistration),
		Title:       "No Authentication Method Registration Campaign",
		Description: "Registration enforcement is not enabled. Users are not prompted to register strong authentication methods.",
		Count:       0,
	}

	if data.AzureAuthMethodsPolicy == nil {
		return []types.Finding{finding}
	}

	if !data.AzureAuthMethodsPolicy.RegistrationEnforcement {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoRegistrationCampaignDetector())
}
