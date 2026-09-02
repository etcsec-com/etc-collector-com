package controls

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TokenProtectionDisabledDetector checks if any CA policy enables token protection
type TokenProtectionDisabledDetector struct {
	audit.BaseDetector
}

// NewTokenProtectionDisabledDetector creates a new detector
func NewTokenProtectionDisabledDetector() *TokenProtectionDisabledDetector {
	return &TokenProtectionDisabledDetector{
		BaseDetector: audit.NewBaseDetector("CA_TOKEN_PROTECTION_DISABLED", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
func (d *TokenProtectionDisabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasTokenProtection := false

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State == "enabled" && p.TokenProtectionRequired {
			hasTokenProtection = true
			break
		}
	}

	count := 0
	if !hasTokenProtection {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Token Protection Not Configured",
		Description: "No CA policy enables token protection (token binding). Token theft allows session hijacking.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewTokenProtectionDisabledDetector())
}
