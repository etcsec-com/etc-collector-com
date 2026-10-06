package pim

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PIMNoMFAOnActivationDetector is an advisory detector for PIM MFA settings.
//
// Microsoft Graph exposes whether MFA is required on activation through the
// role management policy's enablement rule (unifiedRoleManagementPolicyEnablementRule.
// enabledRules containing "MultiFactorAuthentication" - learn.microsoft.com/
// en-us/graph/api/resources/unifiedrolemanagementpolicyenablementrule). The
// Azure provider (internal/providers/azure/client.go, outside this detector's
// scope) does not collect that rule, so this detector cannot tell a
// tenant that requires MFA on activation from one that doesn't - it stays an
// unconditional advisory once PIM-eligible assignments are found, not a
// per-tenant measurement.
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
	// Check if any PIM-eligible assignments exist (indicating activation is
	// in use). IsEligible is the field the sibling PIM detectors
	// (pim-long-activation.go, pim-no-approval-required.go) use for this same
	// test; !IsPermanent is not equivalent - it also matches active
	// assignments with a fixed end date, which never go through activation
	// and so have no "MFA on activation" setting to be missing.
	hasEligibleAssignments := false
	for _, ra := range data.AzureRoleAssignments {
		if ra.IsEligible {
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
