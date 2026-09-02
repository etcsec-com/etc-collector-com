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
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "No CA Policy Targeting Admin Roles",
		Description: "No CA policy specifically targets administrative directory roles.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoPolicyAdminsDetector())
}
