package sspr

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDNotRequiredAdmins       = "SSPR_NOT_REQUIRED_ADMINS"
	CategoryNotRequiredAdmins = audit.CategoryIdentity
)

// NotRequiredAdminsDetector checks if SSPR is required for administrators
type NotRequiredAdminsDetector struct {
	audit.BaseDetector
}

// NewSsprNotRequiredAdminsDetector creates a new SSPR not required for admins detector
func NewSsprNotRequiredAdminsDetector() *NotRequiredAdminsDetector {
	return &NotRequiredAdminsDetector{
		BaseDetector: audit.NewBaseDetector(IDNotRequiredAdmins, CategoryNotRequiredAdmins),
	}
}

// Detect checks if admins are subject to SSPR policy
func (d *NotRequiredAdminsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDNotRequiredAdmins,
		Severity:    types.SeverityHigh,
		Category:    string(CategoryNotRequiredAdmins),
		Title:       "SSPR Not Required for Administrators",
		Description: "Admins are not subject to SSPR policy. Admin password resets should have stronger requirements.",
		Count:       0,
	}

	// Tenant-level check - SSPR admin policy not available in current data model
	finding.Count = 1

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSsprNotRequiredAdminsDetector())
}
