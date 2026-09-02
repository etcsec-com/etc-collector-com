package emergency

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// EmergencyNoExclusionDetector checks if CA policies have exclusions for emergency accounts
type EmergencyNoExclusionDetector struct {
	audit.BaseDetector
}

// NewEmergencyNoExclusionDetector creates a new detector
func NewEmergencyNoExclusionDetector() *EmergencyNoExclusionDetector {
	return &EmergencyNoExclusionDetector{
		BaseDetector: audit.NewBaseDetector("PA_EMERGENCY_NO_EXCLUSION", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *EmergencyNoExclusionDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasProperExclusions := false

	// Check if CA policies targeting all users have exclusions
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}

		// Check if policy targets all users
		includesAllUsers := false
		for _, target := range policy.IncludeUsers {
			if target == "All" {
				includesAllUsers = true
				break
			}
		}

		// If targets all users and has exclusions, proper break-glass pattern exists
		if includesAllUsers && len(policy.ExcludeUsers) > 0 {
			hasProperExclusions = true
			break
		}
	}

	count := 0
	if !hasProperExclusions {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Emergency Accounts Not Excluded from CA",
		Description: "CA policies targeting all users do not exclude any accounts. Break-glass accounts must be excluded from CA policies to prevent lockout. Configure emergency access accounts and exclude them from all CA policies.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewEmergencyNoExclusionDetector())
}
