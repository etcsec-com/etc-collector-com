package sspr

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	ID       = "SSPR_NOT_ENABLED"
	Category = audit.CategoryIdentity
)

// SsprNotEnabledDetector checks if SSPR is enabled
type SsprNotEnabledDetector struct {
	audit.BaseDetector
}

// NewSsprNotEnabledDetector creates a new SSPR not enabled detector
func NewSsprNotEnabledDetector() *SsprNotEnabledDetector {
	return &SsprNotEnabledDetector{
		BaseDetector: audit.NewBaseDetector(ID, Category),
	}
}

// Detect checks if Self-Service Password Reset is enabled for all users
func (d *SsprNotEnabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        ID,
		Severity:    types.SeverityHigh,
		Category:    string(Category),
		Title:       "Self-Service Password Reset Not Enabled",
		Description: "SSPR is not enabled for all users. Without SSPR, users must contact helpdesk for password resets.",
		Count:       0,
	}

	// Per-user IsSSPREnabled, aggregated into UserRegistrationStats.SSPREnabled
	// (authmethods.go) from /reports/authenticationMethods/userRegistrationDetails.
	// There is no tenant-wide SSPR policy field to read instead - Graph does
	// not expose one, only this per-user rollup.
	if data.AzureAuthMethodsDetail != nil && data.AzureAuthMethodsDetail.UserRegistrationStats != nil {
		stats := data.AzureAuthMethodsDetail.UserRegistrationStats
		if stats.Total > 0 {
			finding.Count = stats.Total - stats.SSPREnabled
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSsprNotEnabledDetector())
}
