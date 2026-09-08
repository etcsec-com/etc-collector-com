package controls

import (
	"context"
	"strings"

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
	// data.AzureConditionalAccessPolicies[].TokenProtectionRequired is a flat
	// field convertConditionalAccessPolicy never assigns - the real signal
	// lives in the nested detail slice (sessionControls.tokenProtection.isEnabled),
	// same source already fixed for BL_TOKEN_PROTECTION_ENABLED (baselinesecurity.go).
	// nil means the detail slice was never collected (Policy.Read.All likely
	// missing) - no verdict, never guess.
	if data.AzureConditionalAccessPolicyDetails == nil {
		return []types.Finding{{
			Type:        d.ID(),
			Severity:    types.SeverityMedium,
			Category:    string(d.Category()),
			Title:       "Token Protection Not Configured",
			Description: "No CA policy enables token protection (token binding). Token theft allows session hijacking.",
			Count:       0,
		}}
	}

	hasTokenProtection := false
	for i := range data.AzureConditionalAccessPolicyDetails {
		p := &data.AzureConditionalAccessPolicyDetails[i]
		if !strings.EqualFold(p.State, "enabled") {
			continue
		}
		if p.SessionControls != nil && p.SessionControls.TokenProtection != nil && p.SessionControls.TokenProtection.IsEnabled {
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
