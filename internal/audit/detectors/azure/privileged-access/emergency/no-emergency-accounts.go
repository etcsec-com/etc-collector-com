package emergency

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoEmergencyAccountsDetector checks for break-glass account patterns
type NoEmergencyAccountsDetector struct {
	audit.BaseDetector
}

// NewNoEmergencyAccountsDetector creates a new detector
func NewNoEmergencyAccountsDetector() *NoEmergencyAccountsDetector {
	return &NoEmergencyAccountsDetector{
		BaseDetector: audit.NewBaseDetector("PA_NO_EMERGENCY_ACCOUNTS", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *NoEmergencyAccountsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasEmergencyAccountPattern := false

	// Check if any CA policy targets all users with exclusions (break-glass pattern)
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

		// Check if policy has user exclusions (potential break-glass accounts)
		if includesAllUsers && len(policy.ExcludeUsers) > 0 {
			hasEmergencyAccountPattern = true
			break
		}
	}

	count := 0
	if !hasEmergencyAccountPattern {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "No Emergency Access Accounts Detected",
		Description: "No break-glass/emergency access accounts found. Emergency accounts prevent lockout during CA policy misconfigurations or Azure AD outages. Create 2+ cloud-only accounts excluded from all CA policies.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoEmergencyAccountsDetector())
}
