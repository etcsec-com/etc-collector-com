package roles

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminNoCAPolicyDetector checks for CA policies targeting admin roles
type AdminNoCAPolicyDetector struct {
	audit.BaseDetector
}

// NewAdminNoCAPolicyDetector creates a new detector
func NewAdminNoCAPolicyDetector() *AdminNoCAPolicyDetector {
	return &AdminNoCAPolicyDetector{
		BaseDetector: audit.NewBaseDetector("PA_ADMIN_NO_CA_POLICY", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *AdminNoCAPolicyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasPolicyForAdminRoles := false

	// Check if any enabled CA policy targets admin directory roles
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State == "enabled" && len(policy.IncludeRoles) > 0 {
			hasPolicyForAdminRoles = true
			break
		}
	}

	count := 0
	if !hasPolicyForAdminRoles {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "No CA Policy for Administrative Roles",
		Description: "No Conditional Access policy specifically targets admin directory roles. Administrative roles should be protected by CA policies requiring MFA, compliant devices, and other security controls.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminNoCAPolicyDetector())
}
