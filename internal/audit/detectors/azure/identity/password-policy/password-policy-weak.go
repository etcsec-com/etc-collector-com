package passwordpolicy

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	ID       = "PASSWORD_POLICY_WEAK"
	Category = audit.CategoryIdentity
)

// PasswordPolicyWeakDetector checks if password policy is weak
type PasswordPolicyWeakDetector struct {
	audit.BaseDetector
}

// NewPasswordPolicyWeakDetector creates a new weak password policy detector
func NewPasswordPolicyWeakDetector() *PasswordPolicyWeakDetector {
	return &PasswordPolicyWeakDetector{
		BaseDetector: audit.NewBaseDetector(ID, Category),
	}
}

// Detect checks if Azure AD password policy is sufficiently strong
func (d *PasswordPolicyWeakDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        ID,
		Severity:    types.SeverityHigh,
		Category:    string(Category),
		Title:       "Weak Password Policy",
		Description: "Azure AD password policy may not enforce sufficient complexity. Consider Azure AD Password Protection.",
		Count:       0,
	}

	// For Azure AD, this is a configuration check
	// If we have tenant config but no strong indicators, flag it
	if data.AzureTenantConfig != nil {
		// Tenant exists but we can't verify strong password protection is enabled
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPasswordPolicyWeakDetector())
}
