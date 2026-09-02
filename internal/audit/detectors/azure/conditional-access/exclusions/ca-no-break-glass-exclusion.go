package exclusions

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoBreakGlassExclusionDetector checks if CA policies targeting all users have break-glass exclusions
type NoBreakGlassExclusionDetector struct {
	audit.BaseDetector
}

// NewNoBreakGlassExclusionDetector creates a new detector
func NewNoBreakGlassExclusionDetector() *NoBreakGlassExclusionDetector {
	return &NoBreakGlassExclusionDetector{
		BaseDetector: audit.NewBaseDetector("CA_NO_BREAK_GLASS_EXCLUSION", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
func (d *NoBreakGlassExclusionDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasBreakGlassPattern := true

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State != "enabled" {
			continue
		}

		// Check if policy targets all users
		targetsAll := false
		for _, u := range p.IncludeUsers {
			if u == "All" {
				targetsAll = true
				break
			}
		}

		if targetsAll && len(p.ExcludeUsers) == 0 {
			// Found a policy targeting all users with no exclusions
			hasBreakGlassPattern = false
			break
		}
	}

	count := 0
	if !hasBreakGlassPattern {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "No Break-Glass Account Exclusion Pattern",
		Description: "CA policies targeting all users should exclude emergency access (break-glass) accounts to prevent lockout.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoBreakGlassExclusionDetector())
}
