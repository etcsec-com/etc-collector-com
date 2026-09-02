package roles

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GlobalAdminNotMFADetector checks for CA policy requiring MFA for Global Admins
type GlobalAdminNotMFADetector struct {
	audit.BaseDetector
}

// NewGlobalAdminNotMFADetector creates a new detector
func NewGlobalAdminNotMFADetector() *GlobalAdminNotMFADetector {
	return &GlobalAdminNotMFADetector{
		BaseDetector: audit.NewBaseDetector("PA_GLOBAL_ADMIN_NOT_MFA", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *GlobalAdminNotMFADetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasPolicyForGlobalAdmin := false

	// Check if any CA policy specifically targets Global Administrator role with MFA
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}

		// Check if policy includes Global Administrator role
		hasGlobalAdminRole := false
		for _, roleID := range policy.IncludeRoles {
			if roleID == types.AzureRoleGlobalAdmin {
				hasGlobalAdminRole = true
				break
			}
		}

		if !hasGlobalAdminRole {
			continue
		}

		// Check if policy requires MFA
		for _, control := range policy.GrantControls {
			if control == "mfa" {
				hasPolicyForGlobalAdmin = true
				break
			}
		}

		if hasPolicyForGlobalAdmin {
			break
		}
	}

	count := 0
	if !hasPolicyForGlobalAdmin {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Global Admins Without MFA Enforcement",
		Description: "No Conditional Access policy specifically requires MFA for Global Administrator role. Global Administrators should always be protected by MFA due to their extensive privileges.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewGlobalAdminNotMFADetector())
}
