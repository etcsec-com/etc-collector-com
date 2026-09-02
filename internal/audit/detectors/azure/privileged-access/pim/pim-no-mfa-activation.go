package pim

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PIMNoMFAOnActivationDetector is an advisory detector for PIM MFA settings
type PIMNoMFAOnActivationDetector struct {
	audit.BaseDetector
}

// NewPIMNoMFAOnActivationDetector creates a new detector
func NewPIMNoMFAOnActivationDetector() *PIMNoMFAOnActivationDetector {
	return &PIMNoMFAOnActivationDetector{
		BaseDetector: audit.NewBaseDetector("PA_PIM_NO_MFA_ON_ACTIVATION", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *PIMNoMFAOnActivationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Check if any eligible assignments exist (indicating PIM is in use)
	hasEligibleAssignments := false
	for _, ra := range data.AzureRoleAssignments {
		if !ra.IsPermanent {
			hasEligibleAssignments = true
			break
		}
	}

	count := 0
	// Only flag if PIM is being used but MFA settings cannot be verified from current data
	if hasEligibleAssignments {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "PIM Activation Without MFA",
		Description: "PIM may not require MFA on role activation. MFA ensures identity verification before granting privileges. Review PIM role settings in Azure Portal to enable MFA requirement on activation for all privileged roles.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPIMNoMFAOnActivationDetector())
}
