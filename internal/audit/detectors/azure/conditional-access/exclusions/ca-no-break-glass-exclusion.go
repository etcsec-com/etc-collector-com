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
//
// Source: Microsoft Learn, "Manage emergency access admin accounts"
// (learn.microsoft.com/en-us/entra/identity/role-based-access-control/
// security-emergency-access) - "If you use Conditional Access, at least one
// emergency access account needs to be excluded from all conditional access
// policies." The doc doesn't restrict how the exclusion is expressed: it can
// be a named user (ExcludeUsers) or, just as validly, a group the break-glass
// account belongs to (ExcludeGroups) - a common pattern for organizations
// that manage break-glass membership via group rather than per-user entries.
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

		if targetsAll && len(p.ExcludeUsers) == 0 && len(p.ExcludeGroups) == 0 {
			// Found a policy targeting all users with no exclusion of any kind
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
