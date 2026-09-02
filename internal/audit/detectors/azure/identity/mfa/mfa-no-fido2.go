package mfa

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDNoFIDO2       = "MFA_NO_FIDO2"
	CategoryNoFIDO2 = audit.CategoryIdentity
)

// NoFIDO2Detector checks if FIDO2 security keys are enabled
type NoFIDO2Detector struct {
	audit.BaseDetector
}

// NewMfaNoFido2Detector creates a new no FIDO2 detector
func NewMfaNoFido2Detector() *NoFIDO2Detector {
	return &NoFIDO2Detector{
		BaseDetector: audit.NewBaseDetector(IDNoFIDO2, CategoryNoFIDO2),
	}
}

// Detect checks if FIDO2 is enabled
func (d *NoFIDO2Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDNoFIDO2,
		Severity:    types.SeverityMedium,
		Category:    string(CategoryNoFIDO2),
		Title:       "FIDO2 Security Keys Not Enabled",
		Description: "FIDO2 security keys are not enabled. FIDO2 provides phishing-resistant authentication.",
		Count:       0,
	}

	if data.AzureAuthMethodsPolicy == nil {
		return []types.Finding{finding}
	}

	if data.AzureAuthMethodsPolicy.FIDO2.State != "enabled" {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewMfaNoFido2Detector())
}
