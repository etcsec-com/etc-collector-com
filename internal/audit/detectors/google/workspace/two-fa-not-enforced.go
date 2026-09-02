package workspace

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TwoFANotEnforcedDetector detects users without 2FA
type TwoFANotEnforcedDetector struct {
	audit.BaseDetector
}

// NewTwoFANotEnforcedDetector creates a new detector
func NewTwoFANotEnforcedDetector() *TwoFANotEnforcedDetector {
	return &TwoFANotEnforcedDetector{
		BaseDetector: audit.NewBaseDetector("TWO_FA_NOT_ENFORCED", audit.CategoryIdentity),
	}
}

// Detect checks for users without 2FA
func (d *TwoFANotEnforcedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// TODO: Implement when Google provider is connected
	// Will query Admin Directory API for users with isEnforcedIn2Sv=false
	// Users without 2-step verification enrolled = finding

	return []types.Finding{{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "2FA Not Enforced",
		Description: "Google Workspace users without 2-Step Verification. Accounts without 2FA are vulnerable to credential-based attacks.",
		Count:       0,
	}}
}

func init() {
	audit.MustRegister(NewTwoFANotEnforcedDetector())
}
