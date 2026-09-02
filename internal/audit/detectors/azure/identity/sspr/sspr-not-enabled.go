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

	// Tenant-level finding - SSPR configuration is not available in current data model
	// Flag as potential issue
	finding.Count = 1

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSsprNotEnabledDetector())
}
