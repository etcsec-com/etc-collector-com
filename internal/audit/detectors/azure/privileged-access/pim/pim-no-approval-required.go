package pim

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PIMNoApprovalRequiredDetector detects PIM-eligible roles without approval requirement
type PIMNoApprovalRequiredDetector struct {
	audit.BaseDetector
}

// NewPIMNoApprovalRequiredDetector creates a new detector
func NewPIMNoApprovalRequiredDetector() *PIMNoApprovalRequiredDetector {
	return &PIMNoApprovalRequiredDetector{
		BaseDetector: audit.NewBaseDetector("PA_PIM_NO_APPROVAL_REQUIRED", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *PIMNoApprovalRequiredDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.RoleAssignment

	sensitiveRoles := []string{
		"Global Administrator",
		"Privileged Role Administrator",
		"Security Administrator",
		"Exchange Administrator",
		"SharePoint Administrator",
	}

	for _, ra := range data.AzureRoleAssignments {
		if !ra.IsEligible {
			continue
		}

		// Check if sensitive role
		isSensitive := false
		for _, sensitive := range sensitiveRoles {
			if ra.RoleName == sensitive {
				isSensitive = true
				break
			}
		}

		if isSensitive && !ra.RequiresApproval {
			affected = append(affected, ra)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "PIM Activation Without Approval",
		Description: "PIM-eligible privileged roles can be activated without approval. Approval provides an additional security checkpoint for sensitive role activations.",
		Count:       len(affected),
		Details: map[string]interface{}{
			"recommendation": "Require approval for Global Administrator and other highly privileged role activations",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.RoleAssignmentsToAffectedEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPIMNoApprovalRequiredDetector())
}
