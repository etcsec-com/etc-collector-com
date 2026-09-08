package policies

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoPolicyAdminsDetector checks if any CA policy targets admin roles
type NoPolicyAdminsDetector struct {
	audit.BaseDetector
}

// NewNoPolicyAdminsDetector creates a new detector
func NewNoPolicyAdminsDetector() *NoPolicyAdminsDetector {
	return &NoPolicyAdminsDetector{
		BaseDetector: audit.NewBaseDetector("CA_NO_POLICY_ADMINS", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
//
// Scope, precisely: this checks only whether some enabled policy TARGETS at
// least one directory role (IncludeRoles non-empty) - matching Microsoft's
// documented mechanism for admin-scoped policies (Microsoft Learn, "Require
// MFA for administrators with Conditional Access", learn.microsoft.com/
// en-us/entra/identity/conditional-access/policy-old-require-mfa-admin -
// "Include > Directory roles"). It does NOT verify that policy attaches any
// actual grant control (MFA, block, etc. - that's CA_NO_MFA_REQUIREMENT and
// MFA_NOT_ENFORCED_ADMINS' job, not this check's), and it does NOT detect
// admin-equivalent targeting done via a group instead of a directory role.
// The title's claim ("targeting admin roles") stays literally accurate for
// what's implemented; this comment exists so a reader doesn't infer more.
func (d *NoPolicyAdminsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasAdminPolicy := false

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State == "enabled" && len(p.IncludeRoles) > 0 {
			hasAdminPolicy = true
			break
		}
	}

	count := 0
	if !hasAdminPolicy {
		count = 1
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityCritical,
		Category: string(d.Category()),
		Title:    "No CA Policy Targeting Admin Roles",
		Description: "No CA policy specifically targets administrative directory roles (IncludeRoles). " +
			"This checks targeting only - it does not verify a grant control is attached, and does not " +
			"detect admin-equivalent targeting via a group instead of a role.",
		Count: count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoPolicyAdminsDetector())
}
